/* spctrm_scn_ubus.h*/
#ifndef _SPCTRM_SCN_UBUS_H_
#define _SPCTRM_SCN_UBUS_H_

#include <unistd.h>
#include <signal.h>
#include <semaphore.h>
#include <json-c/json.h>
#include <libubox/blobmsg_json.h>
#include <pthread.h>
#include "libubus.h"
#include "spctrm_scn_wireless.h"
#include "spctrm_scn_config.h"
#include "spctrm_scn_dev.h"
#include "spctrm_scn_tipc.h"

#define MAX_CHANNEL_NUM 200

enum {
    BAND,
    CHANNEL_BITMAP,
    SCAN_TIME,
    __SCAN_MAX
};

enum {
    TOTAL,
    CONFIG,
    MODULE_DIR,
    TMP_DIR,
    TAR_DIR,
    __RLOG_NOTIFY_MAX
};

enum {
    NAME,
    OPTION,
    OLD_VALUE,
    NEW_VALUE,
    __RLOG_CONFIG_MAX
};

void spctrm_scn_ubus_thread();

#endif
