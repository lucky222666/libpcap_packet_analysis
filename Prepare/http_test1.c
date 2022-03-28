//问题在于：载荷捕获部分存在乱码 cookie 和  CRC 
//sln:
// 1 表中的payload字段采用二进制数据类型，可以是
//    binary(长度)类型
//    varbinary(长度）类型
//    blob类型：取大2的16次方-1
//   这些二进制类型存储的就是原始的二进制数据(二进制仍然需要解析，且与DNS的数据包特别处理的初衷相违背)

// 2 表中的payload字段为varchar类型，则只存储外部文件的文件名，将从数据包取出的载荷放在外部文件中(外部文件结果也是二进制数据，查看不方便)
// 3 表中的payload字段为varchar(1500)或text，写入前采用isprint(ch)和sprintf()，将不可打印字符变为可打印字符（如 . )，但这样会破坏载荷的数据结构

#include<pcap.h>
#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include <limits.h>
#include <errno.h>
#include<ctype.h>
#include<errno.h>
#include<string.h>
#include<mysql.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>


//定义抓取包的最大字节数(max bytes per packet to capture)
#define SNAP_LEN 1700		//>1518B

//以太网数据头大小通常为14B,校验位4B 1500+18
#define SIZE_ETHERNET 14

//以太网地址通常是6B
#define ETHER_ADDR_LEN 6

//Ethernet header
struct sniff_ethernet{
	u_char ether_dhost[ETHER_ADDR_LEN];	//dst mac
	u_char ether_shost[ETHER_ADDR_LEN];	//src mac
	u_short ether_type;			//protocol type
};

//IP header
struct sniff_ip{
	u_char ip_vhl;		//version<<4|header len>>2
	u_char ip_tos;		//type of service
	u_short ip_len;		//total length
	u_short ip_id;		//identification
	u_short ip_off;		//fragment offset field
	#define IP_RF 0x8000	//Reserved fragment flag
	#define IP_DF 0x4000	//dont fragment flag
	#define IP_MF 0x2000	//more fragment flag
	#define IP_OFFMASK 0x1fff	//mask for fragmenting bits
	u_char ip_ttl;		//time to live
	u_char ip_p;		//protocol
	u_short ip_sum;		//checksum
	struct in_addr ip_src,ip_dst;
};

//IP头总长度
#define IP_HL(ip)	(((ip)->ip_vhl)&0x0f)
//版本信息
#define IP_V(ip)	(((ip)->ip_vhl)>>4)

//标记+偏移量暂时不处理

//TCP header
typedef u_int tcp_seq;

struct sniff_tcp{
	u_short th_sport;	//src port
	u_short th_dport;	//dst port
	tcp_seq	th_seq;		//sequence number
	tcp_seq ack;		//acknowledgement number
	u_char th_offx2;	//data offset and rsvd= 9 bits
	#define TH_OFF(th) (((th)->th_offx2&0xf0)>>4)
	u_char th_flags;	//six bits flags
	#define TH_FIN 0x01
	#define TH_SYN 0x02
	#define TH_RST 0x04
	#define TH_PUSH 0x08
	#define TH_ACK 0x10
	#define TH_URG 0x20
	#define TH_ECE 0x40
	#define TH_CWR 0x80
	#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;		//window
	u_short th_sum;		//checksum
	u_short th_urp;		//urgent pointer
};

//declare function first
void got_packet(u_char *args,const struct pcap_pkthdr *header,const u_char *packet);
void print_payload(const u_char *payload,int len);
void print_hex_ascii_line(const u_char *payload,int len,int offset);
void print_app_usage(void);
char *stringToBinary(char *s);


char *stringToBinary(char *s)
{
  if (s == NULL) {
    // NULL might be 0 but you cannot be sure about it
    return NULL;
  }
  // get length of string without NUL
  size_t slen = strlen(s);

  // we cannot do that here, why?
  // if(slen == 0){ return s;}

  errno = 0;
  // allocate "slen" (number of characters in string without NUL)
  // times the number of bits in a "char" plus one byte for the NUL
  // at the end of the return value
  char *binary = malloc(slen * CHAR_BIT + 1);
  if(binary == NULL){
     fprintf(stderr,"malloc has failed in stringToBinary(%s): %s\n",s, strerror(errno));
     return NULL;
  }
  // finally we can put our shortcut from above here
  if (slen == 0) {
    *binary = '\0';
    return binary;
  }
  char *ptr;
  // keep an eye on the beginning
  char *start = binary;
  int i;

  // loop over the input-characters
  for (ptr = s; *ptr != '\0'; ptr++) {
    /* perform bitwise AND for every bit of the character */
    // loop over the input-character bits
    for (i = CHAR_BIT - 1; i >= 0; i--, binary++) {
      *binary = (*ptr & 1 << i) ? '1' : '0';
    }
  }
  // finalize return value
  *binary = '\0';
  // reset pointer to beginning
  binary = start;
  return binary;
}

//print help text
void print_app_usage(void)
{
	printf("Usage XXX  [interface]\n");
	printf("\n");
	printf("Options:\n");
	printf("	interface	Listen on<interface> for packets.\n");
	printf("\n");

	return ;
}

//print data in row of 16B:offset hex ascii
//00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1.. */
void print_hex_ascii_line(const u_char *payload,int len,int offset)
{
	int i;
	int gap;
	const u_char *ch;

	//offset
	printf("%05d	",offset);

	//hex
	ch=payload;
	for(i=0;i<len;i++){
		printf("%02x ",*ch);
		ch++;
		//print extra space after 8th byte for visual aid
		if(i==7)
			printf(" ");
	}
	//print space to handle line less than 8 byte
	if(len<8)
		printf(" ");

	//fill hex gap with spaces if not full line
	if(len<16){
		gap=16-len;
		for(i=0;i<gap;i++)
			printf("   ");
	}
	printf("   ");

	//ascii(if printable)
	ch=payload;
	for(i=0;i<len;i++){
		if(isprint(*ch))
			printf("%c",*ch);
		else
		    printf(".");
		ch++;
	}

	printf("\n");

	return ;
}

//print packet payload data
void print_payload(const u_char *payload, int len)
{
	int len_rem=len;
	int line_width=16;			//每行的字节数
	int line_len;
	int offset=0;				//偏移量从0开始计数
	const u_char *ch=payload;

	if(len<0)
		return;

	//data first on one line
	if(len<=line_width){
		print_hex_ascii_line(ch,len,offset);
		return;
	}

	//data spans multiple lines
	for(;;){
		line_len=line_width%len_rem;
		print_hex_ascii_line(ch,line_len,offset);
		//compute total remaining
		len_rem=len_rem-line_len;
		//shift ptr to remaining bytes to print
		ch=ch+line_len;
		//add offset
		offset=offset+line_width;
		//check if we have line width chars or less
		if(len_rem<=line_width){
			//print last line and get out
			print_hex_ascii_line(ch,len_rem,offset);
			break;
		}
	}
	return;
}



//callback function
void got_packet(u_char *args,const struct pcap_pkthdr *header,const u_char *packet)
{
	static int count=1;		//采集数据包的数量

	//declare ptrs to packet headers头头头
	const struct sniff_ethernet *ethernet;		//以太网帧头
	const struct sniff_ip *ip;					//IP报头
	const struct sniff_tcp *tcp;				//TCP段头
	const char *payload;						//有效载荷

	//带有可选部分，是动态变化的，需要记录
	int size_ip;
	int size_tcp;
	int size_payload;

	printf("\nPacket number %d:\n",count);
	count++;

	//define ethernet header处理帧数据
	ethernet=(struct sniff_ethernet*)(packet);

	//define/compute ip header offset强制类型转换，将前14B转换为struct sniff_ethernet结构体
	ip=(struct sniff_ip*)(packet+SIZE_ETHERNET);

	//IP 头实际长度
	size_ip=IP_HL(ip)*4;

	//IP 数据包出错
	if(size_ip<20){
		printf("*Invalid header length:%u bytes\n",size_ip);
		return;
	}

	//print src and dst ip addr
	printf("From:%s\n",inet_ntoa(ip->ip_src));
	printf("To:%s\n",inet_ntoa(ip->ip_dst));

	//determine protocol
	switch(ip->ip_p){
		case IPPROTO_TCP:
			printf("Protocol: TCP\n");
			break;
		case IPPROTO_UDP:
			printf("Protocol: UDP\n");
			return;
		case IPPROTO_ICMP:
			printf("Protocol: ICMP\n");
			return;
		case IPPROTO_IP:
			printf("Protocol: IP\n");
			return;
		default:
			printf("Protocol: unknown\n");
			return;
	}
	
	/*	 *  OK, this packet is TCP.	 */
	/* define/compute tcp header offset */
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);

	size_tcp = TH_OFF(tcp)*4;
	//将被宏定义替换，从而计算出段头长度

	//TCP 段头出错
	if (size_tcp < 20) {
		printf("*Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}
	
	printf("Src port: %d\n", ntohs(tcp->th_sport));
	printf("Dst port: %d\n", ntohs(tcp->th_dport));
	
	/* define/compute tcp payload (segment) offset */
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

	/* compute tcp payload (segment) size */
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
	
	/*	 * Print payload data; it might be binary, so don't just	 * treat it as a string. */
	if (size_payload > 0) {
		printf("Payload (%d bytes):\n", size_payload);
		print_payload(payload, size_payload);
	}

    MYSQL conn;    
    int res;
    char insert_query[SNAP_LEN]="";
    mysql_init(&conn);    //初始化连接句柄
    if ((mysql_real_connect(&conn, "localhost", "root", "", "Capture", 0, NULL, 0)) &&  (ntohs(tcp->th_sport)==80||ntohs(tcp->th_dport)==80)) {
        printf("connect mysql successful\n");              
        //存储入库
        memset(insert_query, 0, sizeof(insert_query));

        stringToBinary(payload);
        sprintf(insert_query, "insert into http_test values('%d','%s','%s','%d','%d','%d','%d','%s')", \
				count-1, inet_ntoa(ip->ip_src),inet_ntoa(ip->ip_dst),ntohs(tcp->th_sport),ntohs(tcp->th_dport),ip->ip_p,ntohs(ip->ip_len)+SIZE_ETHERNET,payload);
		

		insert_query[SNAP_LEN]='\0';
        printf("SQL语句: %s\n", insert_query);
        res = mysql_query(&conn, insert_query);                
        if (!res) {
            printf("Insert %lu rows\n", (unsigned long)mysql_affected_rows(&conn));
        }                
        else {
            fprintf(stderr, "Insert error %d: %s\n", mysql_errno(&conn),mysql_error(&conn));
        }                
        
		//尝试将负载读出
		char select_query[100];
		MYSQL_RES * result;
	    MYSQL_ROW row;

		sprintf(select_query,"select payload from http_test where id = %d",count-1);
		if (mysql_query(&conn, select_query) != 0) {
                fprintf(stderr, "查询失败\n");
                exit(1);
            }                
        else {                
            if ((result = mysql_store_result(&conn)) == NULL) {
                    fprintf(stderr, "保存结果集失败\n");
                    exit(1);
            }                   
            else {                        
        	        while ((row = mysql_fetch_row(result)) != NULL) {
            	        printf("payload is %s , ", row[0]);
                    }
                }
            }
			
		//关闭连接
        mysql_close(&conn);
               
    }  
	    else {
        fprintf(stderr, "Connection failed or it is not HTTP packet\n");
        if (mysql_errno(&conn)) {
        fprintf(stderr, "Connection error %d: %s\n", mysql_errno(&conn),mysql_error(&conn));
        }
    }
 
    return;
}

int main(int argc, char **argv)
{
	const char *fname="traffic.pcap";	//filename
	char *dev = NULL;			/* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;				/* packet capture handle句柄 */

	char filter_exp[] = "ip";		/* filter expression [3]对PF说只要IP格式的数据包 */	
	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask子网掩码 */
	bpf_u_int32 net;			/* ip */
	int num_packets = 100;			/* number of packets to capture */


	/* check for capture device name on command-line */
	if (argc == 2) {
		dev = argv[1];
	}
	else if (argc > 2) {
		fprintf(stderr, "error: unrecognized command-line options\n\n");
		print_app_usage();		//出错了才会调用此函数
		exit(EXIT_FAILURE);
	}
	else {
		/* find a capture device if not specified on command-line */
		dev = pcap_lookupdev(errbuf);			//采集数据包的物理网卡
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n",errbuf);
			exit(EXIT_FAILURE);
		}
	}
	
	/* get network number and mask associated with capture device */			
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",dev, errbuf);
		net = 0;
		mask = 0;
	}

	/* print capture info 写在前面*/
	printf("Device: %s\n", dev);
	printf("Number of packets: %d\n", num_packets);
	printf("Filter expression: %s\n", filter_exp);


	handle = pcap_open_offline(fname,errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	//设置链路类型，以太网
	/* make sure we're capturing on an Ethernet device [2] */
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
	}

	//转换为符合PF的结构体&优化
	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}
	
	//加载到PF中
	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	//循环连续捕获数据包，回调函数是got_packet
	/* now we can set our callback function */
	pcap_loop(handle, num_packets, got_packet, NULL);

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);

	printf("\nCapture complete.\n");

return 0;
}
