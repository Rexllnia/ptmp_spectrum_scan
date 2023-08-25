#ifndef _SPCTRM_SCN_RLOG_H_
#define _SPCTRM_SCN_RLOG_H_

#include "spctrm_scn_config.h"
#include <libubox/blobmsg_json.h>
#include "libubus.h"

#define MAX_RLOG_SERVER_ADDR_LEN 1024

enum {
    RLOG_DISABLE,
    RLOG_ENABLE,
};

void spctrm_scn_rlog_init();
int spctrm_scn_rlog_get_module_enable();
void spctrm_scn_rlog_get_server_addr();
void spctrm_scn_rlog_get_module_server_addr();
#endif
