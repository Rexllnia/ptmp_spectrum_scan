/* spctrm_scn_config.h */
#ifndef _SPCTRM_SCN_CONFIG_H_
#define _SPCTRM_SCN_CONFIG_H_

#include "spctrm_scn_common.h"

#define SN_LEN 14

#define MIN_SCAN_TIME 15 
#define MAX_SCAN_TIME 60
#define EXPIRE_TIME 14

#define POPEN_CMD_ENABLE

#define ETH_ALEN 6

#define POPEN_BUFFER_MAX_SIZE   8192

#define BW_20 20
#define BW_40 40
#define BW_80 80
#define BW_160 160

#define SCAN_BUSY       1
#define SCAN_IDLE       2
#define SCAN_NOT_START  0
#define SCAN_TIMEOUT  	3
#define SCAN_ERROR  	-1

#define FAIL       -1
#define SUCCESS    0

#define BRIDGE_PLATFORM

#define MAX_DEVICE_NUM 5
#define BAND_5G_MAX_CHANNEL_NUM 36

#define BAND_5G     5
#define BAND_2G     2

#define AP_MODE  0
#define CPE_MODE 1
uint8_t g_mode;

#define debug(...)  do {\
                    printf("file : %s line: %d func: %s -->",__FILE__,__LINE__,__func__); \
                    printf(__VA_ARGS__);\
                    printf("\r\n"); \
} while(0)

struct param_input {
    uint64_t channel_bitmap;
    uint8_t band;
    uint8_t channel_num;
    uint8_t scan_time;
    struct uloop_timeout timeout;
};

struct channel_info {
    uint8_t channel;
    uint8_t floornoise;
    uint8_t utilization;
    uint8_t bw;
    uint8_t obss_util;
    uint8_t tx_util;
    uint8_t rx_util;
    double score;
    double rate;
};

#endif
