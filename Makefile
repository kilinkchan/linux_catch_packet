world: cathch_packet.o
	$(CC) $(LDFLAGS) cathch_packet.o -o cathch_packet -lpcap

cathch_packet.o: cathch_packet.o
	$(CC) $(LDFLAGS) -c cathch_packet.c
clean:
	rm *.o cathch_packet
