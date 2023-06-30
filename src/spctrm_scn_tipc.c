
#include "spctrm_scn_tipc.h"
#include "spctrm_scn_config.h"
#include "spctrm_scn_dev.h"
#include <netinet/in.h>
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>

extern volatile int g_status;
extern unsigned char g_mode;
extern struct user_input g_input;
extern struct device_list g_finished_device_list,g_device_list;
extern struct channel_info g_channel_info_5g[36];
extern struct channel_info realtime_channel_info_5g[36];
extern pthread_mutex_t g_mutex;
extern sem_t g_semaphore;

static sem_t receive_finish_semaphore;

int spctrm_scn_tipc_send_start_msg(struct device_list *list,int wait_sec) 
{
	
	struct device_info *p;
	__u32 instant = 0;
	int i;
	
	memset(list,0,sizeof(struct device_list));
	spctrm_scn_dev_wds_list(list);
	list_for_each_device(p,i,list) {
		if (strcmp(p->role,"ap") != 0) {
			instant = spctrm_scn_common_mac_2_nodeadd(p->mac);
			debug("send to mac %x",p->mac);
			spctrm_scn_tipc_send(instant,SERVER_TYPE_SCAN,sizeof(g_input),&g_input);
		}	
	}
}

int spctrm_scn_tipc_send_get_msg(struct device_list *dst_list,int wait_sec) 
{
	struct device_info *p;
	__u32 instant;
	int i;
	char hello[19] = "client get message";

	list_for_each_device(p,i,dst_list) {
		if (strcmp(p->role,"ap") != 0 && p->finished_flag != FINISHED ) {	
			instant = spctrm_scn_common_mac_2_nodeadd(p->mac);
			printf("line : %d fun : %s instant : %x \r\n",__LINE__,__func__,instant);
			spctrm_scn_tipc_send(instant,SERVER_TYPE_GET,sizeof(hello),hello);
		}	
	}

	for (i = 0;i < 3;i++) {
		sleep(1);
		if (spctrm_scn_dev_chk_stat(&g_device_list) == SUCCESS)
		{
			return SUCCESS;
		}
	}
	return FAIL;
}

int spctrm_scn_tipc_send_auto_get_msg(struct device_list *dst_list,int wait_sec) 
{
	struct device_info *p;
	__u32 instant;
	int i;
	char hello[19] = "client get message";

	list_for_each_device(p,i,dst_list) {
		if (strcmp(p->role,"ap") != 0 && p->finished_flag != FINISHED ) {	
			instant = spctrm_scn_common_mac_2_nodeadd(p->mac);
			printf("line : %d fun : %s instant : %x \r\n",__LINE__,__func__,instant);
			spctrm_scn_tipc_send(instant,SERVER_TYPE_AUTO_GET,sizeof(hello),hello);
		}	
	}

	for (i = 0;i < 3;i++) {
		sleep(1);
		if (spctrm_scn_dev_chk_stat(&g_device_list) == SUCCESS)
		{
			return SUCCESS;
		}
	}
	return FAIL;
}

static int wait_for_server(__u32 name_type, __u32 name_instance, int wait)
{
	struct sockaddr_tipc topsrv;
	struct tipc_subscr subscr;
	struct tipc_event event;

	
	int sd = socket(AF_TIPC, SOCK_SEQPACKET, 0);

	memset(&topsrv, 0, sizeof(topsrv));
	topsrv.family = AF_TIPC;
	topsrv.addrtype = TIPC_ADDR_NAME;
	topsrv.addr.name.name.type = TIPC_TOP_SRV;
	topsrv.addr.name.name.instance = TIPC_TOP_SRV;

	/* Connect to topology server */

	if (0 > connect(sd, (struct sockaddr *)&topsrv, sizeof(topsrv))) {
		perror("Client: failed to connect to topology server");

	}

	subscr.seq.type = htonl(name_type);
	subscr.seq.lower = htonl(name_instance);
	subscr.seq.upper = htonl(name_instance);
	subscr.timeout = htonl(wait);
	subscr.filter = htonl(TIPC_SUB_SERVICE);

	if (send(sd, &subscr, sizeof(subscr), 0) != sizeof(subscr)) {
		perror("Client: failed to send subscription");

		close(sd);
		return FAIL;
	}

	/* Now wait for the subscription to fire */
	if (recv(sd, &event, sizeof(event), 0) != sizeof(event)) {
		perror("Client: failed to receive event");

		close(sd);
		return FAIL;
	}


	if (event.event != htonl(TIPC_PUBLISHED)) {
		printf("Client: server {%d,%d} not published within %u [s]\n",
		       name_type, name_instance, wait/1000);
			
		close(sd);
		return FAIL;
		
	}
	close(sd);
}

int spctrm_scn_tipc_send_receive(__u32 dst_instance,__u32 type,size_t payload_size,char *payload)
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

	if(wait_for_server(SERVER_TYPE, ntohl(dst_instance), 100) == FAIL) {
		return FAIL;
	}
	
	pkt_size = sizeof(tipc_recv_packet_head_t) + payload_size;
	pkt = (char*)malloc(pkt_size * sizeof(char));
	memset(mac,0,sizeof(mac));
    spctrm_scn_common_read_file("/proc/rg_sys/sys_mac",mac,sizeof(mac) - 1);
    src_instant = spctrm_scn_common_mac_2_nodeadd(mac);

	memcpy(pkt+sizeof(tipc_recv_packet_head_t),payload,payload_size);
	head = (tipc_recv_packet_head_t *)pkt;
	

	head->instant = src_instant;
	head->type = type;
	head->payload_size = payload_size;


	sd = socket(AF_TIPC, SOCK_RDM, 0);

	server_addr.family = AF_TIPC;
	server_addr.addrtype = TIPC_ADDR_NAME;
	server_addr.addr.name.name.type = SERVER_TYPE;
	server_addr.addr.name.name.instance = ntohl(dst_instance);
	server_addr.addr.name.domain = 0;
    
    setsockopt(sd,SOL_SOCKET,SO_SNDTIMEO,(char*)&timeout,sizeof(struct timeval));
	if (0 > sendto(sd, pkt, pkt_size, 0,
	                (struct sockaddr*)&server_addr, sizeof(server_addr))) {
		perror("Client: failed to send");
		exit(1);
	}
	close(sd);

	return SUCCESS;

}
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

	if(wait_for_server(SERVER_TYPE, ntohl(dst_instance), 100) == FAIL) {
		return FAIL;
	}
	
	pkt_size = sizeof(tipc_recv_packet_head_t) + payload_size;
	pkt = (char*)malloc(pkt_size * sizeof(char));
	memset(mac,0,sizeof(mac));
    spctrm_scn_common_read_file("/proc/rg_sys/sys_mac",mac,sizeof(mac) - 1);
    src_instant = spctrm_scn_common_mac_2_nodeadd(mac);

	memcpy(pkt+sizeof(tipc_recv_packet_head_t),payload,payload_size);
	head = (tipc_recv_packet_head_t *)pkt;
	

	head->instant = src_instant;
	head->type = type;
	head->payload_size = payload_size;


	sd = socket(AF_TIPC, SOCK_RDM, 0);

	server_addr.family = AF_TIPC;
	server_addr.addrtype = TIPC_ADDR_NAME;
	server_addr.addr.name.name.type = SERVER_TYPE;
	server_addr.addr.name.name.instance = ntohl(dst_instance);
	server_addr.addr.name.domain = 0;
    
    setsockopt(sd,SOL_SOCKET,SO_SNDTIMEO,(char*)&timeout,sizeof(struct timeval));
	if (0 > sendto(sd, pkt, pkt_size, 0,
	                (struct sockaddr*)&server_addr, sizeof(server_addr))) {
		perror("Client: failed to send");
		exit(1);
	}
	close(sd);

	return FAIL;

}

void *spctrm_scn_tipc_thread(void * argv)
{

	struct sockaddr_tipc server_addr;
	struct sockaddr_tipc client_addr;
	socklen_t alen = sizeof(client_addr);
	int sd;
	
	tipc_recv_packet_head_t head;
	size_t pkt_size;
	char outbuf[BUF_SIZE] = "Uh ?";
    struct timeval timeout={4,0};
	unsigned char mac[20];
	__u32 instant;

	printf("****** TIPC server program started ******\n\n");

	sem_init(&receive_finish_semaphore,0,0);

    memset(mac,0,sizeof(mac));
    spctrm_scn_common_read_file("/proc/rg_sys/sys_mac",mac,sizeof(mac) - 1);

    instant = spctrm_scn_common_mac_2_nodeadd(mac);

	server_addr.family = AF_TIPC;
	server_addr.addrtype = TIPC_ADDR_NAMESEQ;
	server_addr.addr.nameseq.type = SERVER_TYPE;
	server_addr.addr.nameseq.lower = ntohl(instant);
	server_addr.addr.nameseq.upper = ntohl(instant);
	server_addr.scope = TIPC_ZONE_SCOPE;

	sd = socket(AF_TIPC, SOCK_RDM, 0);

	if (0 != bind(sd, (struct sockaddr *)&server_addr, sizeof(server_addr))) {
		printf("Server: failed to bind port name\n");
		exit(1);
	}
	while (1) {
		char *pkt;
		memset(&head, 0, sizeof(head));
		if (0 >= recvfrom(sd, &head, sizeof(head), MSG_PEEK,
						(struct sockaddr *)&client_addr, &alen)) {
			perror("Server: unexpected message");
		}
		debug("type %d",head.type);
		pkt_size = head.payload_size + sizeof(head);
		debug("pkt_size %d",pkt_size);
		pkt = (char *)malloc(sizeof(char) * pkt_size);
		if (pkt == NULL) {
			debug("malloc FAIL");
			exit(0);
		}
		debug("malloc");
		if (0 >= recvfrom(sd, pkt,pkt_size, 0,
						(struct sockaddr *)&client_addr, &alen)) {
			perror("Server: unexpected message");
		}
		debug("");
		if (head.type == SERVER_TYPE_GET) {
			debug("SERVER_TYPE_GET_REPLY,%d",realtime_channel_info_5g[0].floornoise);
			debug("g_channel_info_5g %d\r\n",g_channel_info_5g[0].floornoise);
			debug("g_status %d",g_status);
			if (g_status == SCAN_BUSY) {
				spctrm_scn_tipc_send(head.instant,SERVER_TYPE_GET_REPLY,sizeof(realtime_channel_info_5g),realtime_channel_info_5g);
			} else {
				debug("g_channel_info_5g %d\r\n",g_channel_info_5g[0].floornoise);
				spctrm_scn_tipc_send(head.instant,SERVER_TYPE_GET_REPLY,sizeof(g_channel_info_5g),g_channel_info_5g);
			}

		} else if (head.type == SERVER_TYPE_GET_REPLY) {
			struct device_info *p;
			int i;
			__u32 instant = 0;
			debug("list len %d",g_finished_device_list.list_len);
			list_for_each_device(p,i,&g_device_list) {
				if (p->finished_flag != FINISHED) {
					instant = spctrm_scn_common_mac_2_nodeadd(p->mac);
					debug("instant : %x ",instant);
					if (instant == head.instant) {			
						memcpy(p->channel_info,pkt+sizeof(tipc_recv_packet_head_t),head.payload_size);
						p->finished_flag = FINISHED;
						debug("p->finished_flag %d",p->finished_flag);
						debug("p->channel_info[0].channel %d",p->channel_info[0].channel); 
						debug("p->channel_info[0].floornoise %d",p->channel_info[0].floornoise);
					}
				}
			}
		} else if (head.type == SERVER_TYPE_AUTO_GET) {
			debug("AUTO GET");
			if (g_status == SCAN_IDLE) {
				spctrm_scn_tipc_send(head.instant,SERVER_TYPE_GET_REPLY,sizeof(g_channel_info_5g),g_channel_info_5g);
			}
		} else if (head.type == SERVER_TYPE_SCAN) {
			debug("SERVER_TYPE_SCAN");
			while (1) {
				debug("g_status %d",g_status);
				if (g_status == SCAN_IDLE || g_status == SCAN_NOT_START) {
					pthread_mutex_lock(&g_mutex);
					memset(realtime_channel_info_5g,0,sizeof(realtime_channel_info_5g));
					memcpy(&g_input,(pkt+sizeof(tipc_recv_packet_head_t)),sizeof(g_input));
					debug("%ld",g_input.channel_bitmap);
					g_status = SCAN_BUSY;
					pthread_mutex_unlock(&g_mutex);
					sem_post(&g_semaphore);
					break;	
				} else if (g_status == SCAN_BUSY) {
					pthread_mutex_lock(&g_mutex);
					g_status = SCAN_TIMEOUT;
					pthread_mutex_unlock(&g_mutex);
				}
			} 
			sem_post(&receive_finish_semaphore);
		}
	debug("free");
	free(pkt);
	}
    return 0;
}

static void server_type_scan_reply_cb() 
{
	
}