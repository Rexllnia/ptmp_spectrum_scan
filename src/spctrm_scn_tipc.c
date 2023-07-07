
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