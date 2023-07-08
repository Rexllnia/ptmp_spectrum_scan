#ifndef _SPCTRM_SCN_RLOG_H_
#define _SPCTRM_SCN_RLOG_H_

#include "spctrm_scn_config.h"
#include <libubox/blobmsg_json.h>
#include "libubus.h"

int spctrm_scn_rlog_module_enable(const char *module);
int spctrm_scn_rlog_module_set(const char *module);
int spctrm_scn_rlog_upload_stream(char *module,char *data);

#endif
