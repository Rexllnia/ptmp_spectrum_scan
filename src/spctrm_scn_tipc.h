/* spctrm_scn_tipc.h */
#ifndef _SPCTRM_SCN_TIPC_H_
#define _SPCTRM_SCN_TIPC_H_

#include <stdio.h>
#include <errno.h>
#include <linux/tipc.h>
#include <time.h>
#include <fcntl.h>
#include <semaphore.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/netlink.h>
#include <linux/socket.h>
#include <pthread.h>
#include <libubox/md5.h>
#include "spctrm_scn_config.h"
#include "spctrm_scn_dev.h"
#include "spctrm_scn_wireless.h"

#define SERVER_TYPE         103
#define SERVER_TYPE_SCAN    18888
#define SERVER_TYPE_GET     102
#define SERVER_TYPE_GET_REPLY  104
#define SERVER_TYPE_AUTO_GET 1222

#define SERVER_INST  17
#define BUF_SIZE 40

typedef struct tipc_recv_packet_head {
    unsigned int type;
    size_t payload_size;
    unsigned int instant;
    time_t timestamp;
    uint8_t port_speed;
    uint8_t port_status;
} tipc_recv_packet_head_t;

typedef struct device_list device_list_t;

int spctrm_scn_tipc_send_get_msg(struct device_list *dst_list,int wait_sec);
int spctrm_scn_tipc_send_start_msg(struct device_list *list,int wait_sec) ;
int spctrm_scn_tipc_send_auto_get_msg(struct device_list *dst_list,int wait_sec) ;
int spctrm_scn_tipc_send(__u32 dst_instance,__u32 type,size_t payload_size,char *payload);
void *spctrm_scn_tipc_thread();

#endif
