#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include "test.h"
#include "ikcp.c"


#define MYPORT 8886

char* SERVERIP = "127.0.0.1";
#define ERR_EXIT(m)  \
    do {      \
    perror(m);   \
    exit(EXIT_FAILURE);  \
    }while(0)
struct sockaddr_in serveraddr;
socklen_t serverlen;
int sock;
int sdsum=0;
//设置非阻塞
static void setnonblocking(int sockfd) {
    int flag = fcntl(sockfd, F_GETFL, 0);
    if (flag < 0) {
        perror("fcntl F_GETFL fail");
        return;
    }
    if (fcntl(sockfd, F_SETFL, flag | O_NONBLOCK) < 0) {
        perror("fcntl F_SETFL fail");
    }
}
// 模拟网络：模拟发送一个 udp包
int udp_output(const char *buf, int len, ikcpcb *kcp, void *user)
{
    // union { int id; void *ptr; } parameter;
	// parameter.ptr = user;
    
	printf("client send :%d packet\n",sdsum);
    int n = sendto(sock,buf,len,0,(struct sockaddr *)&serveraddr,serverlen);
	sdsum++;
	// printf("sendto file:error %d   len%d\n",errno,n);
	return 0;
}

int test(int mode){
    //  kcp对象，第一个参数 conv是会话编号，同一个会话需要相同
	// 最后一个是 user参数，用来传递标识
	ikcpcb *kcp1 = ikcp_create(0x11223344, (void*)0);
    // 设置kcp的下层输出，这里为 udp_output，模拟udp网络输出函数
	kcp1->output = udp_output;

    IUINT32 current = iclock();
	IUINT32 slap = current + 20;
	IUINT32 index = 0;
	IUINT32 next = 0;
	IINT64 sumrtt = 0;
	int count = 0;
	int maxrtt = 0;

    // 配置窗口大小：平均延迟200ms，每20ms发送一个包，
	// 而考虑到丢包重发，设置最大收发窗口为128
	ikcp_wndsize(kcp1, 128, 128);

    // 判断测试用例的模式
	if (mode == 0) {
		// 默认模式
		ikcp_nodelay(kcp1, 0, 10, 0, 0);
	
	}
	else if (mode == 1) {
		// 普通模式，关闭流控等
		ikcp_nodelay(kcp1, 0, 10, 0, 1);

	}	else {
		// 启动快速模式
		// 第二个参数 nodelay-启用以后若干常规加速将启动
		// 第三个参数 interval为内部处理时钟，默认设置为 10ms
		// 第四个参数 resend为快速重传指标，设置为2
		// 第五个参数 为是否禁用常规流控，这里禁止
		ikcp_nodelay(kcp1, 1, 10, 2, 1);

		kcp1->rx_minrto = 10;
		kcp1->fastresend = 1;
	}

    char sdbuffer[2000];
	int hr;

	IUINT32 ts1 = iclock();

    while (1) {
		// isleep(1);
		current = iclock();
		
		ikcp_update(kcp1, iclock());
		// 每隔 20ms，kcp1发送数据
		for (; current >= slap; slap += 20) {
			((IUINT32*)sdbuffer)[0] = index++;
			((IUINT32*)sdbuffer)[1] = current;
			// 发送上层协议包
			ikcp_send(kcp1, sdbuffer, 8);
		}
		
		// int n = sendto(sock,sdbuffer,sizeof(sdbuffer),0,(struct sockaddr *)&serveraddr,serverlen);
	
		// printf("sendto file:error %d   len%d\n",errno,n);
        // deal packet from udpserver
		while (1) {
			serverlen=sizeof(serveraddr);
            memset(sdbuffer,0,sizeof(sdbuffer));
            hr=recvfrom(sock,sdbuffer,sizeof(sdbuffer),0,  \
                NULL,NULL);
			// isleep(1);
            if(hr<=0)
            {
                if(errno==EINTR)
                    continue;
                // ERR_EXIT("recvfrom error"); 
                break;
            }
			// printf("ikcp_input work\n");
			// isleep(1);
            //recvfrom data
			ikcp_input(kcp1, sdbuffer, hr);
			// printf("client rcv :%s\n",sdbuffer);
		}

        // parse data from udpserver
		while (1) {
			hr = ikcp_recv(kcp1, sdbuffer, 10);
			// 没有收到包就退出
			if (hr < 0) break;
			IUINT32 sn = *(IUINT32*)(sdbuffer + 0);
			IUINT32 ts = *(IUINT32*)(sdbuffer + 4);
			IUINT32 rtt = current - ts;
			
			if (sn != next) {
				// 如果收到的包不连续
				printf("ERROR sn %d<->%d\n", (int)count, (int)next);
				break;
			}

			next++;
			sumrtt += rtt;
			count++;
			if (rtt > (IUINT32)maxrtt) maxrtt = rtt;

			printf("[RECV] mode=%d sn=%d rtt=%d\n", mode, (int)sn, (int)rtt);
		}
		if (next > 10) break;
    }
    ts1 = iclock() - ts1;

	ikcp_release(kcp1);
	

	const char *names[3] = { "default", "normal", "fast" };
	printf("%s mode result (%dms):\n", names[mode], (int)ts1);
	printf("avgrtt=%d maxrtt=%d \n", (int)(sumrtt / count), (int)maxrtt);
	float Throughput=(float)count/(float)ts1;
	int loss=sdsum-count;
	float PDR= (float)count/(float)sdsum;
	// float Mdelay=;
	printf("Throughput=%.2f Packet loss=%d Packet delivery ratio=%.2f ",Throughput,loss,PDR);
	printf("press enter to next ...\n");
	char ch; scanf("%c", &ch);
    return 0;
}

int main()
{
	 int reuse = 0;
    if((sock=socket(PF_INET,SOCK_DGRAM,0))<0)
        ERR_EXIT("socket fail");
	setnonblocking(sock);
    memset(&serveraddr,0,sizeof(serveraddr));
    serveraddr.sin_family=AF_INET;
    serveraddr.sin_port=htons(MYPORT);
    serveraddr.sin_addr.s_addr=inet_addr(SERVERIP);
	char sdbuffer[2000]={0};
	// int hr;
	// errno=0;
    // int n = sendto(sock,sdbuffer,sizeof(sdbuffer),0,(struct sockaddr *)&serveraddr,serverlen);
	
	printf("send begin,please enter mode :\n");
	int mode;
	scanf("%d",&mode);
	switch(mode)
	{
		case 0: test(0);break;
		case 1: test(1);break;
		case 2:	test(2);break;
		default : printf("mode error\n");
	}
	// test(0);
	// test(1);
	// test(2);
    return 0;
}