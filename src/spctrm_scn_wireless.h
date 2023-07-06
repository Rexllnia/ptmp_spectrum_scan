/* spctrm_scn_wireless.h */
#ifndef _COUNTRY_CHANNEL_H_
#define _COUNTRY_CHANNEL_H_

#include <json-c/json.h>
#include "lib_unifyframe.h"
#include "spctrm_scn_config.h"
#include "spctrm_scn_dev.h"

#ifdef  BRIDGE_PLATFORM

#define MAX_CHANNEL_NUM     200
#define MAX(a, b) ((a) > (b) ? (a) : (b))

struct country_channel_info {
    char frequency[8];
    int channel;
};

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

#endif /* BRIDGE_PLATFORM */
#endif

