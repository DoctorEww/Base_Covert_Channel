#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/**
    This function decodes a packet's length into a byte.
    @param payload: the string to decode the length of.
    @return length(payload) % 256 if length(payload) % 256 > 128,
            (length(payload) % 256) +  128 otherwise.
*/ 
unsigned char decode_length(char* payload) {
    unsigned char payload_length = (char)(strlen(payload) % 256);
    if (payload_length <= 128) {
        payload_length += 128;
    }
    return payload_length;
}


/**
    This function encodes a byte into a string of appropriate length
    @param byte: the byte to encode into the length of the string.
    @return a pointer to the head of the payload string of appropriate length.
*/ 
char* encode_length(unsigned char byte) {
    char* payload_str = malloc((int)byte);
    unsigned char i = 0;
    for (i = 0; i < byte; i++) {
        *(payload_str + i) = (rand() % 256);    //TODO - seed the random number table
    }
    return payload_str;
}