/*
 * Copyright (C) 2011-2014 Felix Fietkau <nbd@openwrt.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
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
#include "spctrm_scn_dev.h"
#include "spctrm_scn_ubus.h"
#include "lib_unifyframe.h"
#include "spctrm_scn_config.h"
#include "spctrm_scn_rlog.h"





static void server_main(void)
{
    int ret;
    if (g_mode == AP_MODE) {

    } else if (g_mode == CPE_MODE) {

    }

    spctrm_scn_ubus_task();

    spctrm_scn_tipc_task();

    uloop_run();
}

int main(int argc, char **argv)
{
    int ret;

    FILE *fp;
    spctrm_scn_common_cmd("mkdir /tmp/spectrum_scan",NULL);
    fp = fopen("/tmp/spectrum_scan/curl_pid","w+");
    if (fp == NULL) {
        return 0;
    }

    fprintf(fp,"%d",getpid());
    fclose(fp);


    uloop_init();
    server_main();

    debug("done");
    tipc_close();
    spctrm_scn_ubus_close();
    uloop_done();

	return 0;
}




