#ifndef _DEVICE_LIST_H_
#define _DEVICE_LIST_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/netlink.h>
#include <linux/socket.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <json-c/json.h>
#include "spctrm_scn_config.h"
#include "spctrm_scn_tipc.h"

#define ROLE_STR_LEN 4
#define FINISHED 	1
#define NOT_FINISH	0

struct device_info {
    char series_no[SN_LEN];
    unsigned char mac[20];
    char role[ROLE_STR_LEN];
    int status;
    struct channel_info bw20_channel_info[36];
    struct channel_info bw40_channel_info[18];
    struct channel_info bw80_channel_info[9];
    unsigned char finished_flag;
    time_t timestamp;
};
struct device_list {
    int list_len;
    struct device_info device[32];
};

/* 
p: type device_info loop
i: counter
dev_list : type device_list
*/
#define list_for_each_device(p,i,dev_list) \
    for ((p) = (dev_list)->device,i = 0;i < (dev_list)->list_len;p++,i++)

int spctrm_scn_dev_chk_stat(struct device_list *device_list);
int spctrm_scn_dev_find_by_sn(struct device_list *device_list,char *series_no);
void spctrm_scn_dev_reset_stat(struct device_list *list);
int spctrm_scn_dev_list_cmp(struct device_list *src_list,struct device_list *dest_list);
struct device_info *spctrm_scn_dev_find_ap(struct device_list *device_list);
#endif
