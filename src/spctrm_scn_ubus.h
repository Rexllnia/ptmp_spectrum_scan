/* spctrm_scn_ubus.h*/
#ifndef _SPCTRM_SCN_UBUS_H_
#define _SPCTRM_SCN_UBUS_H_

#include <unistd.h>
#include <signal.h>
#include <semaphore.h>
#include <json-c/json.h>
#include <libubox/blobmsg_json.h>
#include "libubus.h"
#include "spctrm_scn_wireless.h"
#include "spctrm_scn_config.h"
#include "spctrm_scn_dev.h"
#include "spctrm_scn_tipc.h"

#define MAX_CHANNEL_NUM 200 

enum {
    BAND,
    CHANNEL_LIST,
    SCAN_TIME,
    __SCAN_MAX
};

struct spctrm_scn_ubus_set_request
{
    struct ubus_request_data req;
    struct uloop_timeout timeout;
    uint64_t channel_bitmap;
    uint8_t scan_time;
    struct device_info device_info;
    int fd;
    int idx;
    char data[];
};

void spctrm_scn_ubus_task(void);
void spctrm_scn_ubus_close();
#endif
