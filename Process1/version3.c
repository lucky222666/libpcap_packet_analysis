#include<pcap.h>
#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<unistd.h>
#include<ctype.h>
#include<errno.h>
#include<string.h>
#include<mysql.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<pthread.h>


//定义抓取包的最大字节数(max bytes per packet to capture)
#define SNAP_LEN 1700		//>1518B

//以太网数据头大小通常为14B,校验位4B 1500+18
#define SIZE_ETHERNET 14

//以太网地址通常是6B
#define ETHER_ADDR_LEN 6

//数据库的长连接
MYSQL conn;    
int res;
char insert_query[SNAP_LEN]="";

//载荷写入文件
FILE *out;
char source[16];
char dest[16];
char string[8]={0};


//多线程实现新增全局变量
static int count=1;		//采集数据包的数量
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
int protocol;

//declare ptrs to packet headers头头头
const struct sniff_ethernet *ethernet;		//以太网帧头
const struct sniff_ip *ip;					//IP报头
const struct sniff_tcp *tcp;				//TCP段头
const struct sniff_udp *udp;                //UDP段头
const char *payload;						//有效载荷

//带有可选部分，是动态变化的，需要记录
int size_ip;
int size_tcp;
int size_udp;
int size_payload;


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


//UDP header
struct sniff_udp{
    u_short th_sport;       //源端口号
    u_short th_dport;       //目的端口号
    u_short udp_len;        //UDP长度
    u_short checksum;       //校验和
};


//declare function first
void got_packet(u_char *args,const struct pcap_pkthdr *header,const u_char *packet);
void print_payload(const u_char *payload,int len);
void print_hex_ascii_line(const u_char *payload,int len,int offset);
void print_app_usage(void);
void capture_dns (void *packet);
void capture_http (void *packet);
void capture_udp (void *packet);
void capture_tcp (void *packet);
void capture_other (void *packet);
void increase_num(void *packet);
char* itoa(int num,char* str,int radix);

char* itoa(int num,char* str,int radix)
{
    char index[]="0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";//索引表
    unsigned unum;//存放要转换的整数的绝对值,转换的整数可能是负数
    int i=0,j,k;//i用来指示设置字符串相应位，转换之后i其实就是字符串的长度；转换后顺序是逆序的，有正负的情况，k用来指示调整顺序的开始位置;j用来指示调整顺序时的交换。
 
    //获取要转换的整数的绝对值
    if(radix==10&&num<0)//要转换成十进制数并且是负数
    {
        unum=(unsigned)-num;//将num的绝对值赋给unum
        str[i++]='-';//在字符串最前面设置为'-'号，并且索引加1
    }
    else unum=(unsigned)num;//若是num为正，直接赋值给unum
 
    //转换部分，注意转换后是逆序的
    do
    {
        str[i++]=index[unum%(unsigned)radix];//取unum的最后一位，并设置为str对应位，指示索引加1
        unum/=radix;//unum去掉最后一位
 
    }while(unum);//直至unum为0退出循环
 
    str[i]='\0';//在字符串最后添加'\0'字符，c语言字符串以'\0'结束。
 
    //将顺序调整过来
    if(str[0]=='-') k=1;//如果是负数，符号不用调整，从符号后面开始调整
    else k=0;//不是负数，全部都要调整
 
    char temp;//临时变量，交换两个值时用到
    for(j=k;j<=(i-1)/2;j++)//头尾一一对称交换，i其实就是字符串的长度，索引最大值比长度少1
    {
        temp=str[j];//头部赋值给临时变量
        str[j]=str[i-1+k-j];//尾部赋值给头部
        str[i-1+k-j]=temp;//将临时变量的值(其实就是之前的头部值)赋给尾部
    }
 
    return str;//返回转换后的字符串
 
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

void increase_num(void *packet) {
    	/*加锁*/
        if (pthread_mutex_lock(&mutex) != 0) {
           perror("pthread_mutex_lock");
           exit(EXIT_FAILURE);
        }
        count++;
        //执行不同数据包协议下的操作
        switch (protocol)
        {
            case 1:
                capture_dns(packet);
                break;
            case 2:
                capture_http(packet);
                break;
            case 3:
                capture_other(packet);
                break;
            case 4:
                capture_tcp(packet);
                break;
            case 5:
                capture_udp(packet);
                break;
        }

    	/*解锁*/
        if (pthread_mutex_unlock(&mutex) != 0) {
            perror("pthread_mutex_unlock");
            exit(EXIT_FAILURE);
        }
		return;
}

//callback function
void got_packet(u_char *args,const struct pcap_pkthdr *header,const u_char *packet)
{
    //定义线程编号
    int ret_thrd1, ret_thrd2, ret_thrd3, ret_thrd4,ret_thrd5;
    pthread_t thread1, thread2, thread3, thread4, thread5;

	printf("\nPacket number %d:\n",count);
    //通过加锁，保证count变量在进行变更的时候，只有一个线程能够取到，并在在该线程对其进行操作的时候，其它线程无法对其进行访问。
	//count++;  将此操作放在线程函数中，用于锁住数据

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
	memcpy(source,inet_ntoa(ip->ip_src),16);
	memcpy(dest,inet_ntoa(ip->ip_dst),16);
	
	printf("From:%s\n",inet_ntoa(ip->ip_src));
	printf("To:%s\n",inet_ntoa(ip->ip_dst));

	//determine protocol
	switch(ip->ip_p){
		case IPPROTO_TCP:
			printf("Protocol: TCP\n");
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
            
            //如果是HTTP协议
            if(ntohs(tcp->th_sport)==80||ntohs(tcp->th_dport)==80)
            {
                protocol=2;
                ret_thrd1 = pthread_create(&thread1, NULL, (void *)&increase_num, (void *)packet);
                if (ret_thrd1 != 0) {
                    printf("为http创建线程失败\n");
                } else {
                    //线程创建成功之后，程序的执行流变成两个，一个执行函数increase_num，一个继续向下执行。
                    pthread_join(thread1, NULL);
                        // if (ret == 0)
                        // {
                        //     printf( "pthread_join success\n");
                        //     return ret;
                        // }
                        // else
                        // {
                        //     printf( "pthread_join failed info: %s\n", strerror(ret));
                        //     return ret;
                        // }
                }
            }
            //如果是纯种TCP协议
            else
            {
                protocol=4;
                ret_thrd2 = pthread_create(&thread2, NULL,  (void *)&increase_num, (void *)packet);   
                if (ret_thrd2 != 0) {
                    printf("线程tcp创建失败\n");
                } else {
                    //线程创建成功之后，程序的执行流变成两个，一个执行函数increase_num，一个继续向下执行。
                  	pthread_join(thread2, NULL);
                }
            }
            break;
		case IPPROTO_UDP:
			printf("Protocol: UDP\n");
            udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);

	        size_udp = 8;
	
	        printf("Src port: %d\n", ntohs(udp->th_sport));
	        printf("Dst port: %d\n", ntohs(udp->th_dport));
			
            //如果是DNS协议
            if(ntohs(udp->th_sport)==53||ntohs(udp->th_dport)==53)
            {
                protocol=1;
                ret_thrd3 = pthread_create(&thread3, NULL,  (void *)&increase_num, (void *)packet);
                if (ret_thrd3 != 0) {
                    printf("线程dns创建失败\n");
                } else {
                    pthread_join(thread3, NULL);
                }
            }
            //如果是纯种UDP协议
            else
            {
                protocol=5;
                ret_thrd4 = pthread_create(&thread4, NULL,  (void *)&increase_num, (void *)packet); 
                if (ret_thrd4 != 0) {
                    printf("线程udp创建失败\n");
                } else {
                    pthread_join(thread4, NULL);
                }  
            }
            break;
		default:
			printf("Protocol: unknown\n");
            protocol=3;
            ret_thrd5 = pthread_create(&thread5, NULL,  (void *)&increase_num, (void *)packet);   
            if (ret_thrd5 != 0) {
                printf("线程other创建失败\n");
            } else {
                pthread_join(thread5, NULL);
            }
           break;
	}

    return;

}

/*	 *  OK, this packet is DNS.	 */
	/* define/compute udp header offset */
void capture_dns (void *packet)
{
	/* define/compute udp payload (segment) offset */
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_udp);

	/* compute udp payload (segment) size */
	size_payload = ntohs(ip->ip_len) - (size_ip + size_udp);
	
	/*	 * Print payload data; it might be binary, so don't just	 * treat it as a string. */
	if (size_payload > 0) {
		printf("Payload (%d bytes)\n", size_payload);
		//print_payload(payload, size_payload);
	}

     //存储入库
    memset(insert_query, 0, sizeof(insert_query));

    sprintf(insert_query, "insert into dns values('%d','%s','%s','%d','%d','%d','%d','')", \
			count-1, source, dest,ntohs(udp->th_sport),ntohs(udp->th_dport),ip->ip_p,ntohs(ip->ip_len)+SIZE_ETHERNET,payload);


	insert_query[SNAP_LEN]='\0';
    printf("SQL语句: %s\n", insert_query);
    res = mysql_query(&conn, insert_query);                
    if (!res) {
        printf("Insert %lu rows\n", (unsigned long)mysql_affected_rows(&conn));
    }                
    else {
        fprintf(stderr, "Insert error %d: %s\n", mysql_errno(&conn),mysql_error(&conn));
    }                

    return;
}

/*	 *  OK, this packet is HTTP.	 */
/* define/compute tcp header offset */
void capture_http (void *packet)
{	
	/* define/compute tcp payload (segment) offset */
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

	/* compute tcp payload (segment) size */
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
	
	/*	 * Print payload data; it might be binary, so don't just	 * treat it as a string. */
	if (size_payload > 0) {
		printf("Payload (%d bytes)\n", size_payload);
		//print_payload(payload, size_payload);
	}

    //存储入库
    memset(insert_query, 0, sizeof(insert_query));

    sprintf(insert_query, "insert into http values('%d','%s','%s','%d','%d','%d','%d','')", \
			count-1, source, dest,ntohs(tcp->th_sport),ntohs(tcp->th_dport),ip->ip_p,ntohs(ip->ip_len)+SIZE_ETHERNET);


	if(ntohs(tcp->th_dport)==80){
		if(chdir("/home/lucky222/Mid-term-Professional-Practice/Process1/HTTP_REQUEST")!=0)
		{
			printf("chdir error");
			exit(1);
		}
		itoa(count-1,string,10);
		out = fopen(string,"w+");      //读写打开或建立一个二进制文件，允许读和写
		if(out == NULL){
			exit(EXIT_FAILURE);
		}
		
		fwrite(payload,1500,1,out);
		fclose(out);
	}

	insert_query[SNAP_LEN]='\0';
    printf("SQL语句: %s\n", insert_query);
    res = mysql_query(&conn, insert_query);                
    if (!res) {
        printf("Insert %lu rows\n", (unsigned long)mysql_affected_rows(&conn));
    }                
    else {
        fprintf(stderr, "Insert error %d: %s\n", mysql_errno(&conn),mysql_error(&conn));
    }                
 
    return;
}

/*	 *  OK, this packet is UDP.	 */
/* define/compute udp header offset */
void capture_udp (void *packet)
{    
    	/* define/compute udp payload (segment) offset */
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_udp);

	/* compute udp payload (segment) size */
	size_payload = ntohs(ip->ip_len) - (size_ip + size_udp);
	
	/*	 * Print payload data; it might be binary, so don't just	 * treat it as a string. */
	if (size_payload > 0) {
		printf("Payload (%d bytes)\n", size_payload);
		//print_payload(payload, size_payload);
	}

         
    //存储入库
    memset(insert_query, 0, sizeof(insert_query));

    sprintf(insert_query, "insert into udp values('%d','%s','%s','%d','%d','%d','%d','')", \
				count-1, source, dest,ntohs(udp->th_sport),ntohs(udp->th_dport),ip->ip_p,ntohs(ip->ip_len)+SIZE_ETHERNET,payload);


	insert_query[SNAP_LEN]='\0';
    printf("SQL语句: %s\n", insert_query);
    res = mysql_query(&conn, insert_query);                
    if (!res) {
        printf("Insert %lu rows\n", (unsigned long)mysql_affected_rows(&conn));
    }                
    else {
        fprintf(stderr, "Insert error %d: %s\n", mysql_errno(&conn),mysql_error(&conn));
    }                 

    return;
}

/*	 *  OK, this packet is TCP.	 */
/* define/compute tcp header offset */
void capture_tcp (void *packet)
{
	/* define/compute tcp payload (segment) offset */
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

	/* compute tcp payload (segment) size */
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
	
	/*	 * Print payload data; it might be binary, so don't just	 * treat it as a string. */
	if (size_payload > 0) {
		printf("Payload (%d bytes)\n", size_payload);
		//print_payload(payload, size_payload);
	}

 
    //存储入库
    memset(insert_query, 0, sizeof(insert_query));

    sprintf(insert_query, "insert into tcp values('%d','%s','%s','%d','%d','%d','%d','')", \
			count-1, source, dest,ntohs(tcp->th_sport),ntohs(tcp->th_dport),ip->ip_p,ntohs(ip->ip_len)+SIZE_ETHERNET);


	if(ntohs(tcp->th_dport)==80){
		if(chdir("/home/lucky222/Mid-term-Professional-Practice/Process1/HTTP_REQUEST2")!=0)
		{
			printf("chdir error");
			exit(1);
		}
		itoa(count-1,string,10);
		out = fopen(string,"w+");      //读写打开或建立一个二进制文件，允许读和写
		if(out == NULL){
			exit(EXIT_FAILURE);
		}
		
		fwrite(payload,1500,1,out);
		fclose(out);
	}

	insert_query[SNAP_LEN]='\0';
    printf("SQL语句: %s\n", insert_query);
    res = mysql_query(&conn, insert_query);                
    if (!res) {
        printf("Insert %lu rows\n", (unsigned long)mysql_affected_rows(&conn));
    }                
    else {
        fprintf(stderr, "Insert error %d: %s\n", mysql_errno(&conn),mysql_error(&conn));
    }                
 
    return;
}

//IGMP  or ICMP  or other unknwon packet
void capture_other (void *packet)
{
    /* define/compute other protocol packet payload (segment) offset */
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip);

	/* compute  payload (segment) size */
	size_payload = ntohs(ip->ip_len) - (size_ip);
	
	/*	 * Print payload data; it might be binary, so don't just	 * treat it as a string. */
	if (size_payload > 0) {
		printf("Payload (%d bytes)\n", size_payload);
		//print_payload(payload, size_payload);
	}
          
	//存储入库
    memset(insert_query, 0, sizeof(insert_query));

    sprintf(insert_query, "insert into other values('%d','%s','%s','%d','%d','')", \
			count-1, source, dest,ip->ip_p,ntohs(ip->ip_len)+SIZE_ETHERNET,payload);


	insert_query[SNAP_LEN]='\0';
    printf("SQL语句: %s\n", insert_query);
    res = mysql_query(&conn, insert_query);                
    if (!res) {
        printf("Insert %lu rows\n", (unsigned long)mysql_affected_rows(&conn));
    }                
    else {
        fprintf(stderr, "Insert error %d: %s\n", mysql_errno(&conn),mysql_error(&conn));
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
	int num_packets = 1432818;			/* number of packets to capture */


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

	//数据库的长连接
    mysql_init(&conn);    //初始化连接句柄
    if (mysql_real_connect(&conn, "localhost", "root", "", "Capture", 0, NULL, 0))
	{
		printf("connect mysql successful\n");   

		out = fopen("http_request.txt","w+");      //读写打开或建立一个二进制文件，允许读和写
		if(out == NULL){
			exit(EXIT_FAILURE);
		}
		//循环连续捕获数据包，回调函数是got_packet
		/* now we can set our callback function */
		for(int i=0;i<num_packets;i=i+100)
			pcap_loop(handle, 100, got_packet, NULL);

		fclose(out);
		//关闭连接
		mysql_close(&conn);
	}
	else {
        fprintf(stderr, "Connection failed or it is not DNS packet\n");
        if (mysql_errno(&conn)) {
        fprintf(stderr, "Connection error %d: %s\n", mysql_errno(&conn),mysql_error(&conn));
        }
    }


	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);

	printf("\nCapture complete.\n");

return 0;
}
