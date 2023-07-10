/* spctrm_scn_wireless.h */
#ifndef _COUNTRY_CHANNEL_H_
#define _COUNTRY_CHANNEL_H_

#include <json-c/json.h>
#include "lib_unifyframe.h"
#include "spctrm_scn_config.h"
#include "spctrm_scn_dev.h"

#define list_for_each_bitset(channel_bitmap,i) \
    for (;(i) < sizeof(uint64_t) * 8;(i)++) \
        if (((channel_bitmap) & (((uint64_t)1)<< (i))) != 0)

int spctrm_scn_wireless_country_channel(uint64_t *channel_bitmap,uint8_t *channel_num,uint8_t bw,uint8_t band);

#endif

