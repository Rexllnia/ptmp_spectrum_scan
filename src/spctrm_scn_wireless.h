/* spctrm_scn_wireless.h */
#ifndef _SPCTRM_SCN_WIRELESS_H_
#define _SPCTRM_SCN_WIRELESS_H_

#include <math.h>
#include <json-c/json.h>
#include "spctrm_scn_config.h"
#include "spctrm_scn_dev.h"
#include "spctrm_scn_rlog.h"

#define PORT_STATUS_ON  1
#define PORT_STATUS_OFF 0
#define IP_ADDR_LEN 17
#define MAX_CHANNEL_NUM     200
#define MAX(a, b) ((a) > (b) ? (a) : (b))

struct country_channel_info {
    char frequency[8];
    int channel;
};

struct port_status_list_elem {
    uint8_t speed;
    uint8_t status;
    char ipaddr[IP_ADDR_LEN];
};
struct port_status_list {
    int port_status_list_len;
    struct port_status_list_elem *list; 
};
int spctrm_scn_wireless_check_channel_score(double score);
void spctrm_scn_wireless_multi_user_loss_init();
struct device_info *spctrm_scn_wireless_get_low_performance_dev(struct device_info *device1,struct device_info *device2);
static double spctrm_scn_wireless_get_exp_throughput(struct device_info *device_info);
void spctrm_scn_wireless_set_status();
int spctrm_scn_wireless_get_country_channel_bwlist(uint8_t *bw_bitmap);
void spctrm_scn_wireless_wds_state();
int spctrm_scn_wireless_channel_info(struct channel_info *info,int band);
double spctrm_scn_wireless_channel_score(struct channel_info *info);
void spctrm_scn_wireless_bw80_channel_score (struct device_info *device);
void spctrm_scn_wireless_bw40_channel_score (struct device_info *device);
inline int spctrm_scn_wireless_channel_check(int channel);
int spctrm_scn_wireless_change_channel(int channel);
void *spctrm_scn_wireless_ap_scan_thread();
void *spctrm_scn_wireless_cpe_scan_thread();
int spctrm_scn_wireless_country_channel(int bw,uint64_t *bitmap_2G,uint64_t *bitmap_5G,int band);
int spctrm_scn_wireless_check_status(char *path);
void spctrm_scn_wireless_change_bw(int bw);
int spctrm_scn_wireless_restore_device_info(char *path,struct device_list *device_list);
void spctrm_scn_wireless_rate_filter(struct device_info *device,double *rate);
void spctrm_scn_wireless_port_status_init(struct port_status_list *list);
struct port_status_list_elem *spctrm_scn_wireless_find_uplink_port(struct port_status_list *list,char *ip);
void spctrm_scn_wireless_delete_port_status_list(struct port_status_list *list);

#endif
