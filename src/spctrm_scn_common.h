/* spctrm_scn_common.h */
#ifndef _SPCTRM_SCN_COMMON_H_
#define _SPCTRM_SCN_COMMON_H_

#include <signal.h>
#include <semaphore.h>
#include <unistd.h>
#include <signal.h>
#include <libubox/blobmsg_json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/netlink.h>
#include <linux/socket.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <libubus.h>
#include <json-c/json.h>
#include <uci.h>
#include "spctrm_scn_config.h"

__u32 spctrm_scn_common_mac_2_nodeadd(unsigned char *mac_src);
char spctrm_scn_common_read_file(char *name,char *buf,char len);
int spctrm_scn_common_cmd(char *cmd,char **rbuf);
void spctrm_scn_common_get_sn(char *sn);
int spctrm_scn_common_uci_anonymous_get(char *file, char *type, char *name, char *option, char *buf, int len);

#endif
