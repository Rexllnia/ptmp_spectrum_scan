/* spctrm_scn_wireless.h */
#ifndef _COUNTRY_CHANNEL_H_
#define _COUNTRY_CHANNEL_H_

#include <json-c/json.h>
#include "lib_unifyframe.h"
#include "spctrm_scn_config.h"
#include "spctrm_scn_dev.h"

#define MAX_CHANNEL_NUM         200 
#define MAX(a, b) ((a) > (b) ? (a) : (b))

struct country_channel_info {
    char frequency[8];
    int channel;
};

void spctrm_scn_wireless_wds_state();
static int timeout_func();
int spctrm_scn_wireless_channel_info(struct channel_info *info,int band);
static double calculate_N(struct channel_info *info);
double spctrm_scn_wireless_channel_score(struct channel_info *info);
void spctrm_scn_wireless_bw80_channel_score (struct device_info *device);
void spctrm_scn_wireless_bw40_channel_score (struct device_info *device);

int spctrm_scn_wireless_change_channel(int channel);
void *spctrm_scn_wireless_ap_scan_thread(void *arg);
void *spctrm_scn_wireless_cpe_scan_thread();
int spctrm_scn_wireless_country_channel(int bw,long *bitmap_2G,long *bitmap_5G,int band);
static inline channel_to_bitmap (int channel);
static inline bitmap_to_channel (int bit_set);

#endif

