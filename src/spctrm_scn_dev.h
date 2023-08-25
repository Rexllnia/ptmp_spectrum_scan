#ifndef _SPCTRM_SCN_DEV_H_
#define _SPCTRM_SCN_DEV_H_

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

#define DEV_TYPE_STR_LEN 40
#define ROLE_STRING_LEN 4
#define FINISHED 	1
#define NOT_FINISH	0
#define IP_ADDR_LEN 17

struct device_info {
    char series_no[SN_LEN];
    unsigned char mac[20];
    char role[ROLE_STRING_LEN];
    char dev_type[DEV_TYPE_STR_LEN];
    int wan_speed_cap;
    int port_speed;
    int port_status;
    char user_ip[IP_ADDR_LEN];
    int status;
    int rssi;
    struct user_input input;
    struct channel_info channel_info[36];
    struct channel_info bw40_channel[18];
    struct channel_info bw80_channel[9];
    unsigned char finished_flag;
    time_t timestamp;
};
struct device_list {
    int list_len;
    struct device_info device[MAX_DEVICE_NUM];
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
int spctrm_scn_dev_wds_list(struct device_list *device_list);
void spctrm_scn_dev_reset_stat(struct device_list *list);
int spctrm_scn_dev_list_cmp(struct device_list *src_list,struct device_list *dest_list);
struct device_info *spctrm_scn_dev_find_ap2(struct device_list *device_list);

#endif
