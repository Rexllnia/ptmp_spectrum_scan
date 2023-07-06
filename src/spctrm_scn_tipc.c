
#include "spctrm_scn_tipc.h"
#include "spctrm_scn_config.h"
#include "spctrm_scn_dev.h"
#include <netinet/in.h>
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>

static void server_type_scan_reply_cb(tipc_recv_packet_head_t *head,char *pkt);

extern volatile int g_status;
extern unsigned char g_mode;
extern struct user_input g_input;
extern struct device_list g_finished_device_list,g_device_list;
extern struct channel_info g_channel_info_5g[MAX_BAND_5G_CHANNEL_NUM];
extern struct channel_info realtime_channel_info_5g[MAX_BAND_5G_CHANNEL_NUM];
extern pthread_mutex_t g_mutex,g_finished_device_list_mutex;
extern sem_t g_semaphore;

int spctrm_scn_tipc_send_start_msg(struct device_list *list,int wait_sec) 
{
    
    struct device_info *p;
    __u32 instant = 0;
    int i;
    
    if (list == NULL) {
        return FAIL;
    }

    memset(list,0,sizeof(struct device_list));
    if (spctrm_scn_dev_wds_list(list) == FAIL) {
        return FAIL;
    }
    list_for_each_device(p,i,list) {
        if (strcmp(p->role,"ap") != 0) {
            instant = spctrm_scn_common_mac_2_nodeadd(p->mac);
            debug("send to mac %x",p->mac);
            if (spctrm_scn_tipc_send(instant,SERVER_TYPE_SCAN,sizeof(g_input),&g_input) == FAIL) {
                debug("FAIL");
                return FAIL;
            }
        }	
    }
    return SUCCESS;
}

int spctrm_scn_tipc_send_get_msg(struct device_list *dst_list,int wait_sec) 
{
    struct device_info *p;
    __u32 instant;
    int i;
    char msg[19] = "client get message";

    if (dst_list == NULL) {
        return FAIL;
    }

    list_for_each_device(p,i,dst_list) {
        if (strcmp(p->role,"ap") != 0 && p->finished_flag != FINISHED ) {	
            instant = spctrm_scn_common_mac_2_nodeadd(p->mac);
            debug("line : %d fun : %s instant : %x \r\n",__LINE__,__func__,instant);
            spctrm_scn_tipc_send(instant,SERVER_TYPE_GET,sizeof(msg),msg);
        }	
    }

    for (i = 0;i < 3;i++) {
        sleep(1);
        if (spctrm_scn_dev_chk_stat(&g_device_list) == SUCCESS) {
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
    char msg[19] = "client get message";

    if (dst_list == NULL) {
        return FAIL;
    }

    list_for_each_device(p,i,dst_list) {
        if (strcmp(p->role,"ap") != 0 && p->finished_flag != FINISHED ) {	
            instant = spctrm_scn_common_mac_2_nodeadd(p->mac);
            debug("line : %d fun : %s instant : %x \r\n",__LINE__,__func__,instant);
            spctrm_scn_tipc_send(instant,SERVER_TYPE_AUTO_GET,sizeof(msg),msg);
        }	
    }

    for (i = 0;i < wait_sec;i++) {
        sleep(1);
        if (spctrm_scn_dev_chk_stat(&g_device_list) == SUCCESS) {
            return SUCCESS;
        }
    }
    return FAIL;
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

void *spctrm_scn_tipc_thread()
{

    struct sockaddr_tipc server_addr;
    struct sockaddr_tipc client_addr;
    socklen_t alen = sizeof(client_addr);
    int sd;
    char *pkt;
    tipc_recv_packet_head_t head;
    size_t pkt_size;
    char outbuf[BUF_SIZE] = "Uh ?";
    struct timeval timeout={4,0};
    unsigned char mac[20];
    __u32 instant;

    debug("****** TIPC server program started ******\n\n");

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
    if (sd < 0) {
        return FAIL;
    }

    if (0 != bind(sd, (struct sockaddr *)&server_addr, sizeof(server_addr))) {
        debug("Server: failed to bind port name\n");
        return FAIL;
    }

    while (1) {
        
        pkt = NULL;
        memset(&head, 0, sizeof(head));
        if (0 >= recvfrom(sd, &head, sizeof(head), MSG_PEEK,
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
        if (0 >= recvfrom(sd, pkt,pkt_size, 0,
                        (struct sockaddr *)&client_addr, &alen)) {
            perror("Server: unexpected message");
            free(pkt);
            goto clear;
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
            server_type_scan_reply_cb(&head,pkt); 
        } else if (head.type == SERVER_TYPE_AUTO_GET) {
            debug("AUTO GET");
            if (g_status == SCAN_IDLE) {
                spctrm_scn_tipc_send(head.instant,SERVER_TYPE_GET_REPLY,sizeof(g_channel_info_5g),g_channel_info_5g);
            }
        } else if (head.type == SERVER_TYPE_SCAN) {
            debug("SERVER_TYPE_SCAN");
            if (g_status == SCAN_IDLE || g_status == SCAN_NOT_START) {
                pthread_mutex_lock(&g_mutex);
                memset(realtime_channel_info_5g,0,sizeof(realtime_channel_info_5g));
                memcpy(&g_input,(pkt+sizeof(tipc_recv_packet_head_t)),sizeof(g_input));
                debug("%llu",g_input.channel_bitmap);
                g_status = SCAN_BUSY;
                pthread_mutex_unlock(&g_mutex);
                sem_post(&g_semaphore);
            }
        }
    debug("free");
    free(pkt);
    continue;
clear: 
    (void)recvfrom(sd, &head, sizeof(head),0,(struct sockaddr *)&client_addr, &alen);

    }
    close(sd);
    return 0;
}

static void server_type_scan_reply_cb(tipc_recv_packet_head_t *head,char *pkt) 
{
    struct device_info *p;
    int i;
    __u32 instant = 0;

    if (head == NULL || pkt == NULL) {
        return;
    }

    debug("list len %d",g_finished_device_list.list_len);
    pthread_mutex_lock(&g_finished_device_list_mutex);
    list_for_each_device(p,i,&g_device_list) {
        if (p->finished_flag != FINISHED) {
            instant = spctrm_scn_common_mac_2_nodeadd(p->mac);
            debug("instant : %x ",instant);
            if (instant == head->instant) {			
                memcpy(p->channel_info,pkt+sizeof(tipc_recv_packet_head_t),head->payload_size);
                p->finished_flag = FINISHED;
                debug("p->finished_flag %d",p->finished_flag);
                debug("p->channel_info[0].channel %d",p->channel_info[0].channel); 
                debug("p->channel_info[0].floornoise %d",p->channel_info[0].floornoise);
            }
        }
    }
    pthread_mutex_unlock(&g_finished_device_list_mutex);	
}