#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include "test.h"
#include "ikcp.c"
#define MYPORT 8886

#define ERR_EXIT(m)  \
    do {      \
    perror(m);   \
    exit(EXIT_FAILURE);  \
    }while(0)
struct sockaddr_in clientaddr;
socklen_t clientlen;
int sock;
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
    // printf("server send :%s\n",buf);
    sendto(sock,buf,len,0,(struct sockaddr *)&clientaddr,clientlen);
	return 0;
}

// 测试用例
void test(int mode)
{
	

	// 创建 kcp对象，第一个参数 conv是会话编号，同一个会话需要相同
	// 最后一个是 user参数，用来传递标识
	
	ikcpcb *kcp2 = ikcp_create(0x11223344, (void*)1);

	// 设置kcp的下层输出，这里为 udp_output，模拟udp网络输出函数
	
	kcp2->output = udp_output;

	IUINT32 current = iclock();
	

	// 配置窗口大小：平均延迟200ms，每20ms发送一个包，
	// 而考虑到丢包重发，设置最大收发窗口为128
	
	ikcp_wndsize(kcp2, 128, 128);

	// 判断测试用例的模式
	if (mode == 0) {
		// 默认模式
		
		ikcp_nodelay(kcp2, 0, 10, 0, 0);
	}
	else if (mode == 1) {
		// 普通模式，关闭流控等
		
		ikcp_nodelay(kcp2, 0, 10, 0, 1);
	}	else {
		// 启动快速模式
		// 第二个参数 nodelay-启用以后若干常规加速将启动
		// 第三个参数 interval为内部处理时钟，默认设置为 10ms
		// 第四个参数 resend为快速重传指标，设置为2
		// 第五个参数 为是否禁用常规流控，这里禁止
		ikcp_nodelay(kcp2, 1, 10, 2, 1);
	}


	char rcbuffer[2000];
	int hr;
    

	IUINT32 ts1 = iclock();

	while (1) {
		// isleep(1);
		current = iclock();
		ikcp_update(kcp2, iclock());
        //deal packet from udpclient
        while(1)
        {
            clientlen=sizeof(clientaddr);
            memset(rcbuffer,0,sizeof(rcbuffer));
            hr=recvfrom(sock,rcbuffer,sizeof(rcbuffer),0,  \
                (struct sockaddr*)&clientaddr,&clientlen);
            // isleep(1);
            if(hr<=0)
            {
                 if (errno == EINTR)
                    continue;
                // ERR_EXIT("recvfrom error");
                break;
            }
            // printf("server rcv :%s\n",rcbuffer);
            //recvfrom data
            ikcp_input(kcp2,rcbuffer,hr);
            
        }
        //return data
        while(1){
            hr=ikcp_recv(kcp2,rcbuffer,10);
            if(hr<0)
                break;
            ikcp_send(kcp2,rcbuffer,hr);
        }

	}

	ts1 = iclock() - ts1;
	ikcp_release(kcp2);
    close(sock);
}




int main()
{
    //init socket
    // int sock;
    int reuse = 0;
      
    sock = socket(PF_INET, SOCK_DGRAM,0);
    if(sock<0)
        ERR_EXIT("socket error");
    // if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0)
    // {
    //         perror("setsockopet error\n");
    //         return -1;
    // }
    setnonblocking(sock);
    struct sockaddr_in serveraddr;
    memset(&serveraddr,0,sizeof(serveraddr));
    serveraddr.sin_family=AF_INET;
    serveraddr.sin_port=htons(MYPORT);
    serveraddr.sin_addr.s_addr=htonl(INADDR_ANY);
    
    printf("listen %d port\n",MYPORT);
    if(bind(sock,(struct sockaddr*)&serveraddr,sizeof(serveraddr)) < 0)
        ERR_EXIT("bind error");
    printf("please enter mode:\n");
    // printf("errno %d   \n",errno);
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