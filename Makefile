CC=gcc

interface_to_pcap: interface_to_pcap.c
	$(CC) -o interface_to_pcap interface_to_pcap.c -lpcap

clean:
	rm interface_to_pcap
	rm log.pcap
