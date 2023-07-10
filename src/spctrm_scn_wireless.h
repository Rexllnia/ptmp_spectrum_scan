/* spctrm_scn_wireless.h */
#ifndef _SPCTRM_SCN_WIRELESS_H_
#define _SPCTRM_SCN_WIRELESS_H_

#include <json-c/json.h>
#include "lib_unifyframe.h"
#include "spctrm_scn_config.h"
#include "spctrm_scn_dev.h"
#include "spctrm_scn_ubus.h"

#define list_for_each_bitset(channel_bitmap,i) \
    for (;(i) < sizeof(uint64_t) * 8;(i)++) \
        if (((channel_bitmap) & (((uint64_t)1)<< (i))) != 0)

int spctrm_scn_wireless_country_channel(uint64_t *channel_bitmap,uint8_t *channel_num,uint8_t bw,uint8_t band);
int spctrm_scn_wireless_get_channel_info(struct channel_info *info,int band);
void spctrm_scn_wireless_scan_task(struct uloop_timeout *t);
void spctrm_scn_wireless_channel_scan(struct uloop_timeout *t);

#endif

