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

pthread_mutex_t g_mutex,g_scan_schedule_mutex,g_finished_device_list_mutex;
pthread_t pid1, pid2 ,pid3;
sem_t g_semaphore;


int main(int argc, char **argv)
{
    FILE *fp;
    int ret;

    ret = FAIL;
    sem_init(&g_semaphore,0,0);
    g_input.scan_time = MIN_SCAN_TIME;
    g_status = SCAN_NOT_START;
	g_input.channel_bitmap = 0;
    spctrm_scn_wireless_wds_state ();
    pthread_mutex_init(&g_mutex, NULL);
    pthread_mutex_init(&g_scan_schedule_mutex,NULL);
    pthread_mutex_init(&g_finished_device_list_mutex,NULL);
    
    spctrm_scn_rlog_module_set("spectrum_scan");
    spctrm_scn_rlog_module_enable("spectrum_scan");

    spctrm_scn_common_cmd("mkdir /tmp/spectrum_scan",NULL);
    fp = fopen("/tmp/spectrum_scan/curl_pid","w+");
    if (fp == NULL) {
        return 0;
    }

    fprintf(fp,"%d",getpid());
    fclose(fp);

    if (g_mode == AP_MODE) {
        debug("ap mode");
        if ((pthread_create(&pid1, NULL, spctrm_scn_wireless_ap_scan_thread, NULL)) != 0) {

            return 0;
        }
        if ((pthread_create(&pid3, NULL, spctrm_scn_ubus_thread, NULL)) != 0) {

            return 0;
        }
        if ((pthread_create(&pid2, NULL, spctrm_scn_tipc_thread, NULL)) != 0) {

            return 0;
        }

    } else if (g_mode == CPE_MODE) {
        debug("cpe mode");
        if ((pthread_create(&pid1, NULL, spctrm_scn_wireless_cpe_scan_thread, NULL)) != 0) {

            return 0;
        }
        if ((pthread_create(&pid2, NULL, spctrm_scn_tipc_thread, NULL)) != 0) {

            return 0;
        }

    }

if (g_mode == AP_MODE) {

	if (pthread_join(pid1, NULL) != 0) {
	
		return 0;
    }
	if (pthread_join(pid2, NULL) != 0) {
	
		return 0;
    }
	if (pthread_join(pid3, NULL) != 0) {
	
		return 0;
    }


} else if (g_mode == CPE_MODE) {
    if (pthread_join(pid1, NULL) != 0) {
    
        return 0;
    }
    if (pthread_join(pid2, NULL) != 0) {
        
            return 0;
    }
}

	return 0;
}




