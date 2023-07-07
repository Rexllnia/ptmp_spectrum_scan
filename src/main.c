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
#define PLATFORM_5G_ENABLE
#define BRIDGE_PLATFORM

extern unsigned char g_mode;
extern struct device_list g_finished_device_list;
extern struct device_list g_device_list;
struct channel_info g_channel_info_5g[MAX_BAND_5G_CHANNEL_NUM];
struct channel_info realtime_channel_info_5g[MAX_BAND_5G_CHANNEL_NUM];
extern struct user_input g_input;
volatile int g_status,g_scan_time;
volatile long g_scan_timestamp;
extern long g_bitmap_2G,g_bitmap_5G;

static struct ubus_context *ctx;

static void server_main(void)
{
    int ret;
    if (g_status == AP_MODE) {

    } else if (g_status == CPE_MODE) {

    }
    debug("");
    spctrm_scn_ubus_task();
    debug("");
    // spctrm_scn_tipc_task();
    debug("");
    uloop_run();
}

int main(int argc, char **argv)
{
    int ret;



    uloop_init();
    server_main();

    debug("done");
    // tipc_close();
    spctrm_scn_ubus_close();
    uloop_done();

	return 0;
}




