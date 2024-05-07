#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/un.h>
#include <fcntl.h>
#include <sys/types.h>

#include <pthread.h>

#define PACKET_SIZE 1600
#define PAYLOAD_LEN 1400
#define ICMP_HEADER_SIZE sizeof(struct icmphdr)
#define INTERNAL_SOCK_PORT 12345
#define ICMP_TIMEOUT 100
#define ENCODE_KEY "icmpsecret"

//#define DBG(fmt,...) printf(fmt, ##__VA_ARGS__)
#define DBG(fmt,...)

typedef struct {
	char *ip;
	char *file_name;
	int  id;
	int  lock_socket_port;
	int  lock_socket_recv;
	int  lock_socket_send;
}ICMP_ARGS;

static ICMP_ARGS global_ip[16] = {{0}};
static int ip_cnt = 0;

unsigned short checksum(unsigned short *addr, int len) {
    unsigned int sum = 0;
    while (len > 1) {
        sum += *addr++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(unsigned char *)addr;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

void packet_encode(char *data, size_t length, const char *key) {
    size_t key_length = strlen(key);
    for (size_t i = 0; i < length; ++i) {
        data[i] ^= key[i % key_length];
    }
}

//return icmp reply id
int icmp_reply_wait(int sockfd, int timeout_ms) {
	fd_set readfds;
    struct timeval timeout;
    int ret;

	// 设置超时时间
    timeout.tv_sec = 0;
    timeout.tv_usec = timeout_ms * 1000;

    // 设置文件描述符集合
    FD_ZERO(&readfds);
    FD_SET(sockfd, &readfds);

    // 使用 select 函数进行超时等待
    ret = select(sockfd + 1, &readfds, NULL, NULL, &timeout);
    if (ret == -1) {
        return -1;
    } else if (ret == 0) {
        return 0; //timeout
    } else {
        if (FD_ISSET(sockfd, &readfds)) {
            char buffer[16];
            ssize_t bytesRead = read(sockfd, buffer, sizeof(buffer));
            if (bytesRead == -1) {
                perror("read error\n");
                return -1;
            }

            // 处理接收到的数据
            DBG("[icmp_reply_wait] Recv Seq %s From InternalRecvFd %d\n", buffer, sockfd);
            return ntohs(atoi(buffer));
        }
    }

	return 0;
}

//获取icmp报文
void *icmp_recv_thread(void *arg) {
	int sockfd;
    char packet[PACKET_SIZE];
    struct iphdr *ip_header = (struct iphdr *)packet;
    struct icmphdr *icmp_header = (struct icmphdr *)(packet + sizeof(struct iphdr));
    struct sockaddr_in dest_addr;
    socklen_t addrlen = sizeof(struct sockaddr_in);

    // 创建原始套接字
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        perror("socket");
        return NULL;
    }

    // 接收 ICMP Echo Request
    while (1) {
        memset(packet, 0, PACKET_SIZE);

        // 接收数据包
        if (recvfrom(sockfd, packet, PACKET_SIZE, 0, (struct sockaddr *)&dest_addr, &addrlen) < 0) {
            perror("icmp_recv_thread recvfrom");
            return NULL;
        }

        if (icmp_header->type == ICMP_ECHOREPLY) {
			char seqStr[32] = {0};
			sprintf(seqStr, "%d", icmp_header->un.echo.sequence);

			// 提取 IP 地址
		    char sourceIP[INET_ADDRSTRLEN];
		    inet_ntop(AF_INET, &(ip_header->saddr), sourceIP, INET_ADDRSTRLEN);

			//DBG("[icmp_recv_thread] Recv IcmpReply From %s Seq %s \n", sourceIP, seqStr);

			int i = 0;
			for (; i < ip_cnt; i++) {
				if (strcmp(global_ip[i].ip, sourceIP) == 0) {
					DBG("[icmp_recv_thread] Recv IcmpReply From %s Seq %s \n", sourceIP, seqStr);
					send(global_ip[i].lock_socket_send, seqStr, strlen(seqStr), 0);
					DBG("[icmp_recv_thread] Send InternalSocket Seq %s For %s SendSockFd %d \n", seqStr, sourceIP, global_ip[i].lock_socket_send);
					break;
				}
		    }
    	}
    }	

    // 关闭套接字
    close(sockfd);

	return NULL;
}

int connect_internal_socket(int srcport) {
	int sock = 0;
    struct sockaddr_in serv_addr, client_addr;

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("[connect_internal_socket] Socket creation error \n");
        return -1;
    }

    // 设置客户端地址结构
    memset(&client_addr, 0, sizeof(client_addr));
    client_addr.sin_family = AF_INET;
    //client_addr.sin_addr.s_addr = INADDR_ANY;
    client_addr.sin_port = htons(srcport);

    // 绑定客户端套接字到指定地址和端口
    if (bind(sock, (struct sockaddr *)&client_addr, sizeof(client_addr)) < 0) {
        perror("[connect_internal_socket] bind failed");
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(INTERNAL_SOCK_PORT);

    // 将 IPv4 地址从点分十进制转换为二进制格式
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        printf("[connect_internal_socket] Invalid address/ Address not supported \n");
        return -1;
    }

    // 连接到服务器
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        printf("[connect_internal_socket] Connection Failed \n");
        return -1;
    }

	int i = 0;
	for (i = 0; i < ip_cnt; i++) {
		if(global_ip[i].lock_socket_port == srcport) {
			global_ip[i].lock_socket_send = sock;
			printf("IP %s InternalSendSocket %d OK ...\n", global_ip[i].ip, sock);
			return 0;
		}
	}

	printf("internal error.\n");
	return -1;
}

void *new_icmp(void *arg) {
    int sockfd, ret;
    char packet[PACKET_SIZE];
    //struct iphdr *ip_header = (struct iphdr *)packet;
    //struct icmphdr *icmp_header = (struct icmphdr *)(packet + sizeof(struct iphdr));
	//char *payload = (char *)(packet + sizeof(struct iphdr)+ sizeof(struct icmphdr));

	struct icmphdr *icmp_header = (struct icmphdr *)(packet);
	char *payload = (char *)(packet + sizeof(struct icmphdr));
    struct sockaddr_in dest_addr;
    socklen_t addrlen = sizeof(struct sockaddr_in);

	ICMP_ARGS* icmp_args = (ICMP_ARGS *)(arg);
	char *ip = icmp_args->ip;
	char *file_name = icmp_args->file_name;
	int lock_socket_port = icmp_args->lock_socket_port;
	int fileFd = -1;
	
	printf("Start New ICMP to %s, File %s \n", ip, file_name);

	//connect to internal socket
	ret = connect_internal_socket(lock_socket_port);
	if (ret != 0) {
		printf("[new_icmp] connect_internal_socket error \n");
		exit(-1);
	}

	sleep(1);
	int _cnt = 3;
	do {
		if (icmp_args->lock_socket_recv > 0) {
			break;
		}
	}while(_cnt-- > 0);

	int lock_socket_recv = icmp_args->lock_socket_recv;
	if (lock_socket_recv <= 0) {
		printf("[new_icmp] Ip %s not ready for internal socket \n", ip);
		exit(-1);
	}

	int send_file = 1;
	if (strcmp(file_name, "NULL") == 0) {
		send_file = 0;
	}

	if (send_file) {
		fileFd = open(file_name, O_RDONLY);
		if (fileFd < 0) {
			perror("Failed to open file");
	        return NULL;
		}
	}

    // 创建原始套接字
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        perror("socket");
        return NULL;
    }

    // 设置目的地址
    memset(&dest_addr, 0, sizeof(struct sockaddr_in));
    dest_addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, ip, &(dest_addr.sin_addr)) <= 0) {
        perror("inet_pton");
        return NULL;
    }

    // 构造 ICMP Echo Request
    icmp_header->type = ICMP_ECHO;
    icmp_header->code = 0;
    icmp_header->un.echo.id = getpid();

	int seq = 1;
	int send_len = 0;

	if (send_file) {
		memcpy(payload, file_name, strlen(file_name));
		packet_encode(payload, strlen(file_name), ENCODE_KEY);
		send_len = ICMP_HEADER_SIZE + strlen(file_name);
	}else {
		send_len = ICMP_HEADER_SIZE;
	}
	
	//send file name for seq 1
	icmp_header->un.echo.sequence = htons(seq);
	icmp_header->checksum = 0;
    icmp_header->checksum = checksum((unsigned short *)icmp_header, send_len);

	// 发送 ICMP Echo Request
    _cnt = 5;
    do {
	    if (sendto(sockfd, packet, send_len, 0, (struct sockaddr *)&dest_addr, addrlen) < 0) {
	        perror("sendto");
	        return NULL;
	    }

		DBG("Send Icmp To %s Seq %d PlayLoadLen %d Csum %x \n", ip, seq, 0, icmp_header->checksum);

		// 等待icmp应答
		int reply_seq = icmp_reply_wait(lock_socket_recv, ICMP_TIMEOUT);
		if (reply_seq == 0) {
			printf("Timeout for seq %d ip %s \n", seq, ip);
		}else if (reply_seq < 0) {
			printf("Internal socket err %d ip %s \n", reply_seq, ip);
			return NULL;
		}else {
			if (reply_seq == seq) {
				DBG("Recv Icmp To %s Seq %d \n", ip, seq);
				break;
			}else {
				printf("Error Seq for ip %s now-seq %d reply-seq %d\n", ip, seq, reply_seq);
			}
		}
		
		_cnt--;
	}while(_cnt > 0);
	

	int totalSendLen = 0;
	int readlen = 0;
	while (1) {

		if (send_file) {
			readlen = read(fileFd, payload, PAYLOAD_LEN);
			if (readlen < 0) {
				printf("Read Error \n");
				return NULL;
			}

			if (readlen == 0) {
				printf("%s send ok.\n", file_name);
				return NULL;
			}

			packet_encode(payload, readlen, ENCODE_KEY);
			totalSendLen += readlen;
		}
	
		seq++;
		send_len = ICMP_HEADER_SIZE+readlen;
		icmp_header->un.echo.sequence = htons(seq);
		icmp_header->checksum = 0;
	    icmp_header->checksum = checksum((unsigned short *)icmp_header, send_len);

	    // 发送 ICMP Echo Request
	    int try_cnt = 5;
	    do {
			
		    if (sendto(sockfd, packet, send_len, 0, (struct sockaddr *)&dest_addr, addrlen) < 0) {
		        perror("sendto");
		        return NULL;
		    }

			DBG("Send Icmp To %s Seq %d PlayLoadLen %d Csum %x \n", ip, seq, readlen, icmp_header->checksum);

			// 等待icmp应答
			int reply_seq = icmp_reply_wait(lock_socket_recv, ICMP_TIMEOUT);
			if (reply_seq == 0) {
				printf("Timeout for seq %d ip %s \n", seq, ip);
			}else if (reply_seq < 0) {
				printf("Internal socket err %d ip %s \n", reply_seq, ip);
				return NULL;
			}else {
				if (reply_seq == seq) {
					usleep(10000);
					DBG("Recv Icmp To %s Seq %d \n", ip, seq);
					if (seq % 1000 == 0) {
						printf("SendTo %s Seq %d Len %d \n", ip, seq, totalSendLen);
					}
					break;
				}else {
					printf("Error Seq for ip %s now-seq %d reply-seq %d\n", ip, seq, reply_seq);
				}
			}
			
			try_cnt--;
		}while(try_cnt > 0);
	   
	}
    
    // 关闭套接字
    close(sockfd);

    return NULL;
}

void *internal_socket_accept_thread(void *arg) {
	int server_fd, new_socket;
    struct sockaddr_in address, client_addr;;
    int opt = 1;
    int addrlen = sizeof(address);

	printf("Start Thread internal_socket_accept_thread ...\n");

   // 创建套接字
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("[internal_socket_accept_thread]socket failed");
        exit(EXIT_FAILURE);
    }

    // 设置套接字选项
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("[internal_socket_accept_thread]setsockopt failed");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(INTERNAL_SOCK_PORT);

    // 绑定套接字到指定地址和端口
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("[internal_socket_accept_thread]bind failed");
        exit(EXIT_FAILURE);
    }

    // 监听连接请求
    if (listen(server_fd, 3) < 0) {
        perror("[internal_socket_accept_thread]listen failed");
        exit(EXIT_FAILURE);
    }

    
    DBG("[internal_socket_accept_thread]Server listening on port %d\n", INTERNAL_SOCK_PORT);
	int i = 0;
	while(1) {
	    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen)) < 0) {
	        perror("[internal_socket_accept_thread] accept failed");
	        exit(EXIT_FAILURE);
	    }

		// 获取客户端的地址信息
	    if (getpeername(new_socket, (struct sockaddr *)&client_addr, (socklen_t *)&addrlen) < 0) {
	        perror("[internal_socket_accept_thread] getpeername failed");
	        exit(EXIT_FAILURE);
	    }

	    DBG("[internal_socket_accept_thread] Client IP: %s\n", inet_ntoa(client_addr.sin_addr));
	    DBG("[internal_socket_accept_thread] Client Port: %d\n", ntohs(client_addr.sin_port));

		for (i = 0; i < ip_cnt; i++) {
			if(global_ip[i].lock_socket_port == ntohs(client_addr.sin_port)) {
				global_ip[i].lock_socket_recv = new_socket;
				printf("IP %s InternalRecvSocket %d OK ...\n", global_ip[i].ip, new_socket);
				break;
			}
		}		
	}

    return 0;
} 

int main(void) {
	global_ip[0].file_name = "./test1";
	global_ip[0].id = 0;
	global_ip[0].ip = "8.134.89.147";
	global_ip[0].lock_socket_port = 10001;
	global_ip[0].lock_socket_send = -1;
	global_ip[0].lock_socket_recv = -1;
	ip_cnt++;

	//global_ip[1].file_name = "NULL";
	//global_ip[1].id = 0;
	//global_ip[1].ip = "183.2.172.42";
	//global_ip[1].lock_socket_port = 10002;
	//global_ip[1].lock_socket_send = -1;
	//global_ip[1].lock_socket_recv = -1;
	//ip_cnt++;


	pthread_t thread;
	pthread_create(&thread, NULL, internal_socket_accept_thread, NULL);
	pthread_create(&thread, NULL, icmp_recv_thread, NULL);

	int i = 0;
	for(i = 0; i < ip_cnt; i++) {
		pthread_create(&thread, NULL, new_icmp, (void*)&global_ip[i]);
	}

	while (1) {
		sleep(30);
	}

	return 0;
}

