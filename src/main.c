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
char g_wds_bss[20];
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
    spctrm_scn_wireless_wds_state();
    pthread_mutex_init(&g_mutex, NULL);
    pthread_mutex_init(&g_scan_schedule_mutex,NULL);
    pthread_mutex_init(&g_finished_device_list_mutex,NULL);
    spectrm_scn_debug_init();

    spctrm_scn_common_cmd("mkdir /tmp/spectrum_scan",NULL);
    fp = fopen("/tmp/spectrum_scan/curl_pid","w+");
    if (fp == NULL) {
        return FAIL;
    }

    fprintf(fp,"%d",getpid());
    fclose(fp);

    if (spctrm_scn_wireless_get_wds_bss(g_wds_bss) == FAIL) {
        SPCTRM_SCN_DBG_FILE("\nFAIL\n");
        return FAIL;
    }

    if (g_mode == AP_MODE) {
        if (access("/etc/spectrum_scan/current_channel_info",F_OK) == FAIL) {
            creat("/etc/spectrum_scan/current_channel_info",0777);
        }
        if (access("/etc/spectrum_scan_cache",F_OK) != FAIL) {
            SPCTRM_SCN_DBG_FILE("\nfile exit");
            spctrm_scn_wireless_check_status("/etc/spectrum_scan_cache");
        } else {
            creat("/etc/spectrum_scan_cache",0777);
        }

        SPCTRM_SCN_DBG_FILE("\nap mode");
        SPCTRM_SCN_DBG_FILE("\ng_status %d",g_status);
        if ((pthread_create(&pid1, NULL, spctrm_scn_wireless_ap_scan_thread, NULL)) != 0) {

            return 0;
        }
        if ((pthread_create(&pid2, NULL, spctrm_scn_tipc_thread, NULL)) != 0) {

            return 0;
        }

    } else if (g_mode == CPE_MODE) {
        SPCTRM_SCN_DBG_FILE("\ncpe mode");
        if ((pthread_create(&pid1, NULL, spctrm_scn_wireless_cpe_scan_thread, NULL)) != 0) {

            return 0;
        }
        if ((pthread_create(&pid2, NULL, spctrm_scn_tipc_thread, NULL)) != 0) {

            return 0;
        }
    }

    spctrm_scn_ubus_thread();

    if (pthread_join(pid1, NULL) || pthread_join(pid2, NULL) != 0) {

        return 0;
    }

    return 0;
}




