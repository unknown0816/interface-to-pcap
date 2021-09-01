/*
    Interface to pcap using libpcap library
*/
#include<pcap.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>

void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
void process_ip_packet(const u_char * , int);

FILE *pca;
unsigned int total = 0;

int main()
{
    pcap_if_t *alldevsp , *device;
    pcap_t *handle;

    char errbuf[100] , *devname , devs[100][100];
    int count = 1 , n;

    //First get the list of available devices
    printf("Finding available devices ... ");
    if( pcap_findalldevs( &alldevsp , errbuf) )
    {
        printf("Error finding devices : %s" , errbuf);
        exit(1);
    }
    printf("Done");

    //Print the available devices
    printf("\nAvailable Devices are :\n");
    for(device = alldevsp ; device != NULL ; device = device->next)
    {
        printf("%d. %s - %s\n" , count , device->name , device->description);
        if(device->name != NULL)
        {
            strcpy(devs[count] , device->name);
        }
        count++;
    }

    //Ask user which device to capture
    printf("Enter the number of the device you want to capture : ");
    scanf("%d" , &n);
    devname = devs[n];

    //Open the device for capturing
    printf("Opening device %s for capturing ... " , devname);
    handle = pcap_open_live(devname , 65536 , 1 , 10 , errbuf);

    if (handle == NULL)
    {
        fprintf(stderr, "Couldn't open device %s : %s\n" , devname , errbuf);
        exit(1);
    }
    printf("Done\n");

    //open write binary
    pca = fopen("log.pcap","wb");
    if(pca == NULL)
    {
        printf("Unable to create pcap file.");
        return 1;
    }

    // global pcap header - see https://wiki.wireshark.org/Development/LibpcapFileFormat#Global_Header
    char * gheader = "\xD4\xC3\xB2\xA1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF\x00\x00\x01\x00\x00\x00";
    fwrite(gheader,1,24,pca);
    fclose(pca);

    //Put the device in processing loop
    pcap_loop(handle , -1 , process_packet , NULL);

    return 0;
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
    int size = header->len;

    ++total;

    //open append binary
    pca = fopen("log.pcap","ab");
    if(pca == NULL)
    {
        printf("Unable to open pcap file.");
    } else {
        struct timeval tv;

        // packet header - see https://wiki.wireshark.org/Development/LibpcapFileFormat#Record_.28Packet.29_Header
        gettimeofday(&tv,NULL);
        fwrite(&tv.tv_sec, 1, 4, pca);
        fwrite(&tv.tv_usec, 1, 4, pca);
        fwrite(&size, 1, 4, pca);
        fwrite(&size, 1, 4, pca);

        // packet data
        fwrite(buffer, 1, size, pca);
        fclose(pca);
    }

    printf("Total : %d\r", total);
}

