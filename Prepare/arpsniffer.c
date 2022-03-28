#include<pcap.h>
#include<stdlib.h>
#include<string.h>
#include<arpa/inet.h>

#define ARP_REQUEST 1
#define ARP_REPLY 2

typedef struct arphdr{
	u_int16_t htype;	//hardware type
	u_int16_t ptype;	//protocol type
	u_char hlen;		//hardware address length
	u_char plen;		//protocol address length
	u_int16_t oper;		//operation code
	u_char sha[6];
	u_char spa[4];
	u_char tha[6];
	u_char tpa[4];
}arphdr_t;

#define MAXBYTES2CAPTURE 2048

int main(int argc,char *argv[]){

	int i=0;
	bpf_u_int32 netaddr=0,mask=0;
	struct bpf_program filter;	//place to store the bpf filter program
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *descr=NULL;		//network interface handler
	struct pcap_pkthdr pkthdr;	//packet information
	const unsigned char* packet=NULL;	//raw data
	arphdr_t *arpheader=NULL;	//Pointer to the arp header
	memset(errbuf,0,PCAP_ERRBUF_SIZE);

	if(argc!=2){
		printf("USAGE:arpsniffer<interface>\n");
		exit(1);
	}

	//open a network device for capture
	if((descr=pcap_open_live(argv[1],MAXBYTES2CAPTURE,0,512,errbuf))==NULL){
		fprintf(stderr,"ERROR:%s\n",errbuf);
		exit(1);
	}
	
	//look up infor from the capture device
	if(pcap_lookupnet(argv[1],&netaddr,&mask,errbuf)==-1){
		fprintf(stderr,"ERROR:%s\n",errbuf);
		exit(1);
	}

	//complies the filter expression into a BPF filter program
	if(pcap_compile(descr,&filter,"arp",1,mask)==-1){
		fprintf(stderr,"ERROR:%s\n",pcap_geterr(descr));
		exit(1);
	}

	//load the filter program into the packet capture device
	if(pcap_setfilter(descr,&filter)==-1){
		fprintf(stderr,"ERROR:%s\n",pcap_geterr(descr));
		exit(1);
	}

	while(1){
		if((packet=pcap_next(descr,&pkthdr))==NULL){
			fprintf(stderr,"ERROR:Error getting the packet.\n",errbuf);
			exit(1);
		}

		arpheader=(struct arphdr*)(packet+14);

		//分别取出各个成员项
		printf("\n\nReceived Packet Size:5d bytes\n",pkthdr.len);
		printf("Hardware type:%s\n",(ntohs(arpheader->htype)==-1)?"Etherner":"Unknown");
		printf("Protocol type:%s\n",(ntohs(arpheader->ptype)==0x0800)?"IPv4":"Unknown");
		printf("Operation:%s\n",(ntohs(arpheader->oper)==ARP_REQUEST)?"ARP_Request":"ARP_Reply");

		//print the packet contents
		if(ntohs(arpheader->htype)==1&&ntohs(arpheader->ptype)==0x0800){
			printf("Sender MAC:");

			for(i=0;i<6;i++)
				printf("%02X:",arpheader->sha[i]);
			
			printf("\nSender IP:");

			for(i=0;i<4;i++)
				printf("%d.",arpheader->spa[i]);

			printf("\nTarget MAC:");

			for(i=0;i<6;i++)
				printf("%02X:",arpheader->tha[i]);

			printf("\nTarget IP:");

			for(i=0;i<4;i++)
				printf("%d.",arpheader->tpa[i]);
			
			printf("\n");
		}
	}
	return 0;
}
