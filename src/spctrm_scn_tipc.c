
#include "spctrm_scn_tipc.h"
#include "spctrm_scn_config.h"
#include "spctrm_scn_dev.h"
#include <netinet/in.h>
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>

struct uloop_fd c_fd; 
struct sockaddr_tipc server_addr;
struct sockaddr_tipc client_addr;


int spctrm_scn_tipc_send(__u32 dst_instance,__u32 type,size_t payload_size,char *payload)
{
    int sd;
    struct sockaddr_tipc server_addr;
    struct timeval timeout={4,0};
    __u32 src_instant = 0;
    char mac[20];
    char *pkt;
    tipc_recv_packet_head_t *head;
    size_t pkt_size;
    int j;
    
    if (payload == NULL) {
        return FAIL;
    } 
    
    pkt_size = sizeof(tipc_recv_packet_head_t) + payload_size;
    pkt = (char*)malloc(pkt_size * sizeof(char));
    if (pkt == NULL) {
        debug("FAIL");
        return FAIL;
    }
    memset(mac,0,sizeof(mac));
    spctrm_scn_common_read_file("/proc/rg_sys/sys_mac",mac,sizeof(mac) - 1);
    src_instant = spctrm_scn_common_mac_2_nodeadd(mac);

    memcpy(pkt+sizeof(tipc_recv_packet_head_t),payload,payload_size);
    head = (tipc_recv_packet_head_t *)pkt;
    

    head->instant = src_instant;
    head->type = type;
    head->payload_size = payload_size;


    sd = socket(AF_TIPC, SOCK_RDM, 0);
    if (sd < 0) {
        debug("FAIL");
        free(pkt);
        return FAIL;
    }
    server_addr.family = AF_TIPC;
    server_addr.addrtype = TIPC_ADDR_NAME;
    server_addr.addr.name.name.type = SERVER_TYPE;
    server_addr.addr.name.name.instance = ntohl(dst_instance);
    server_addr.addr.name.domain = 0;
    
    setsockopt(sd,SOL_SOCKET,SO_SNDTIMEO,(char*)&timeout,sizeof(struct timeval));
    if (0 > sendto(sd, pkt, pkt_size, 0,
                    (struct sockaddr*)&server_addr, sizeof(server_addr))) {
        perror("Client: failed to send");
        free(pkt);
        close(sd);
        return FAIL;
    }

    free(pkt);
    close(sd);

    return SUCCESS;

}

void spctrm_scn_tipc_recv_cb(struct uloop_fd *sock, unsigned int events) {
	tipc_recv_packet_head_t head;
	size_t pkt_size;
	socklen_t alen = sizeof(client_addr);
	struct timeval timeout={4,0};
	char *pkt;

    pkt = NULL;
    memset(&head, 0, sizeof(head));
    if (0 >= recvfrom(sock->fd, &head, sizeof(head), MSG_PEEK,
                    (struct sockaddr *)&client_addr, &alen)) {
        perror("Server: unexpected message");
        goto clear;
    }
    debug("type %d",head.type);
    pkt_size = head.payload_size + sizeof(head);
    debug("pkt_size %d",pkt_size);
    pkt = (char *)malloc(sizeof(char) * pkt_size);
    if (pkt == NULL) {
        debug("malloc FAIL");
        goto clear;
    }
    debug("malloc");
    if (0 >= recvfrom(sock->fd, pkt,pkt_size, 0,
                    (struct sockaddr *)&client_addr, &alen)) {
        perror("Server: unexpected message");
        free(pkt);
        goto clear;
    }

    switch (head.type) {
    case PROTOCAL_TYPE_SCAN:
        debug("TYPE_SCAN");
        break;
    case PROTOCAL_TYPE_GET:
        debug("TYPE_GET");
        break;
    default:
        break;
    }

    debug("free");
    free(pkt);
    return;

clear: 
    (void)recvfrom(sock->fd, &head, sizeof(head),0,(struct sockaddr *)&client_addr, &alen);    
}

void spctrm_scn_tipc_task()
{
	unsigned char mac[20];
	__u32 instant;

    memset(mac,0,sizeof(mac));
    spctrm_scn_common_read_file("/proc/rg_sys/sys_mac",mac,sizeof(mac) - 1);

    instant = spctrm_scn_common_mac_2_nodeadd(mac);

	server_addr.family = AF_TIPC;
	server_addr.addrtype = TIPC_ADDR_NAMESEQ;
	server_addr.addr.nameseq.type = SERVER_TYPE;
	server_addr.addr.nameseq.lower = ntohl(instant);
	server_addr.addr.nameseq.upper = ntohl(instant);
	server_addr.scope = TIPC_ZONE_SCOPE;

	c_fd.fd = socket(AF_TIPC, SOCK_RDM, 0);
	if (0 != bind(c_fd.fd, (struct sockaddr *)&server_addr, sizeof(server_addr))) {
		printf("Server: failed to bind port name\n");
		exit(1);
	}
	c_fd.cb = spctrm_scn_tipc_recv_cb;
	uloop_fd_add (&c_fd,ULOOP_READ);	
}

void tipc_close() 
{
    close(c_fd.fd);
}