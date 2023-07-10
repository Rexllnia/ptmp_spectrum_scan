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
#include "spctrm_scn_config.h"
#include "spctrm_scn_dev.h"

#define SERVER_TYPE  103    
#define PROTOCAL_TYPE_SCAN    18888
#define PROTOCAL_TYPE_GET     102

#define SERVER_INST  17
#define BUF_SIZE 40

typedef struct tipc_recv_packet_head {
    unsigned int type;
    size_t payload_size;
    unsigned int instant;
}tipc_recv_packet_head_t;

void spctrm_scn_tipc_task();
void tipc_close();
#endif
