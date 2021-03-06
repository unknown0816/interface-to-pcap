# Interface to PCAP
This is a simple tool for capturing all packets of an interface and convert everything into a PCAP file.

## Information
During the implementation of this tool the lsniffer.c file provided [here](https://gist.github.com/fffaraz/7f9971463558e9ea9545) and [here](https://www.binarytides.com/packet-sniffer-code-c-linux/) was used and adapted.

After starting, the tool fetches all interfaces of the system and prints them to stdout. Via stdin one interface must be selected to be captured. This interface will be used and all packets will be written into a PCAP file named "log.pcap".

## Usage

Building and executing the tool:
```
make
./interface_to_pcap
```

Cleaning the repository (the binary and log.pcap will be deleted):
```
make clean
```

## Further use cases

It is pretty simple to extend this tool with a packet filter or similar to get a more detailed capture.


