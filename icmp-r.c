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
#define ENCODE_KEY "icmpsecret"
#define ICMP_HEADER_SIZE sizeof(struct icmphdr)

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
	int i = 0;
    size_t key_length = strlen(key);
    for (i = 0; i < length; ++i) {
        data[i] ^= key[i % key_length];
    }
}


//获取icmp报文
void *icmp_recv_thread(void *arg) {
	int sockfd;
    char packet[PACKET_SIZE];
    struct iphdr *ip_header = (struct iphdr *)packet;
    struct icmphdr *icmp_header = (struct icmphdr *)(packet + sizeof(struct iphdr));
	char *payload = (char *)(packet + sizeof(struct iphdr) + sizeof(struct icmphdr));
    struct sockaddr_in dest_addr;
    socklen_t addrlen = sizeof(struct sockaddr_in);
	char *src_ip = (char *)arg;

	printf("Start icmp_recv_thread With Ip %s \n", src_ip);

    // 创建原始套接字
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        perror("socket");
        return NULL;
    }

    // 接收 ICMP Echo Request
    int lastSeq = 0;
	int totalLen = 0;
	FILE *file = NULL;
    while (1) {
        memset(packet, 0, PACKET_SIZE);

        // 接收ICMP应答
	    int packet_size = recv(sockfd, packet, PACKET_SIZE, 0);
	    if (packet_size < 0) {
	        perror("recv failed");
	        exit(EXIT_FAILURE);
	    }
		
		//printf("Packet Size %d\n", packet_size);

		if (packet_size < (sizeof(struct iphdr) + sizeof(struct icmphdr))) {
			printf("Error Packet\n");
			continue;
		}

        if (icmp_header->type == ICMP_ECHO) {

			// 提取 IP 地址
		    char sourceIP[INET_ADDRSTRLEN];
		    inet_ntop(AF_INET, &(ip_header->saddr), sourceIP, INET_ADDRSTRLEN);
			if (strcmp(src_ip, sourceIP) != 0) {
				continue;
			}

			int curSeq = ntohs(icmp_header->un.echo.sequence);

			if (curSeq - lastSeq != 1) {
				printf("Recv Seq %d , But now Seq %d \n", curSeq, lastSeq);
				continue;
			}
		
			//name
			if (curSeq == 1) {
				packet_encode(payload, packet_size - sizeof(struct iphdr) - sizeof(struct icmphdr), ENCODE_KEY);
				printf("Get Name %s \n", payload);
				lastSeq = curSeq;

				file = fopen(payload, "w");
				if (NULL == file) {
					printf("Error Open File %s \n", payload);
					exit(-1);
				}

				//send reply
				icmp_header->type = ICMP_ECHOREPLY;
				icmp_header->un.echo.sequence = htons(curSeq);
	            icmp_header->checksum = 0;
	            icmp_header->checksum = checksum((unsigned short *)icmp_header, ICMP_HEADER_SIZE);

	            // 交换源地址和目的地址
	            ip_header->daddr = ip_header->saddr;
	            ip_header->saddr = dest_addr.sin_addr.s_addr;

	            // 发送 ICMP Echo Reply
	            if (sendto(sockfd, packet, ICMP_HEADER_SIZE, 0, (struct sockaddr *)&dest_addr, addrlen) < 0) {
	                perror("sendto");
	                break;
	            }

				continue;
			}

			//save
			int payload_len = packet_size - sizeof(struct iphdr) - sizeof(struct icmphdr);
			totalLen += payload_len;
			packet_encode(payload, payload_len, ENCODE_KEY);
			//printf("Seq %d, Payload [%s] \n", curSeq, payload);
			fwrite(payload, payload_len, 1, file);

			if (curSeq % 1000 == 0) {
				printf("CurSeq %d , Size %d \n", curSeq, payload_len);
			}

			//send reply
			icmp_header->type = ICMP_ECHOREPLY;
			icmp_header->un.echo.sequence = htons(curSeq);
            icmp_header->checksum = 0;
            icmp_header->checksum = checksum((unsigned short *)icmp_header, ICMP_HEADER_SIZE);

            // 交换源地址和目的地址
            ip_header->daddr = ip_header->saddr;
            ip_header->saddr = dest_addr.sin_addr.s_addr;

            // 发送 ICMP Echo Reply
            if (sendto(sockfd, packet, ICMP_HEADER_SIZE, 0, (struct sockaddr *)&dest_addr, addrlen) < 0) {
                perror("sendto");
                break;
            }

			lastSeq = curSeq;
			
    	}
    }	

    // 关闭套接字
    close(sockfd);

	return NULL;
}


int main(int argc, char** argv) {
	if (argc != 2){
		printf("Error Para \n");
		return 0;
	}

	char *ip = argv[1];

	pthread_t thread;
	pthread_create(&thread, NULL, icmp_recv_thread, ip);

	while(1) {
		sleep(30);
	}
}
