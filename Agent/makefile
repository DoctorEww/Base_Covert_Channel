CC=gcc  #compiler
SERVER=server #target file name
AGENT=agent #target file name
all:
	rm -f $(AGENT)
	$(CC) channel_agent.h decode_packet.c client.c -o $(AGENT)

agent: client.c decode_packet.o
	rm -f $(AGENT)
	$(CC) channel_agent.h decode_packet.o agent.c -o $(AGENT)

decode_packet.o: decode_packet.c
	$(CC) -c -o decode_packet.o decode_packet.c


	
clean:
	rm -f $(AGENT)
	rm -f *.o