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

#include "spctrm_scn_ubus.h"

static int scan(struct ubus_context *ctx, struct ubus_object *obj,
              struct ubus_request_data *req, const char *method,
              struct blob_attr *msg);
static int get(struct ubus_context *ctx, struct ubus_object *obj,
              struct ubus_request_data *req, const char *method,
              struct blob_attr *msg);
static int realtime_get(struct ubus_context *ctx, struct ubus_object *obj,
              struct ubus_request_data *req, const char *method,
              struct blob_attr *msg);
static void add_channel_info_blobmsg(struct blob_buf *buf,struct channel_info *channel_info,int channel_num);
static void add_timestamp_blobmsg(struct blob_buf *buf,time_t *timestamp);
static void add_device_info_blobmsg(struct blob_buf *buf,struct device_info *device,int is_real_time);
static void add_score_list_blobmsg(struct blob_buf *buf,int channel_num,struct channel_info *channel_info_list);
static void add_channel_score_blobmsg(struct blob_buf *buf, struct channel_info *channel_info);
static void spctrm_scn_ubus_reconnect_timer(struct uloop_timeout *t);
extern pthread_t pid1, pid2 ,pid3;
extern struct channel_info g_channel_info_5g[MAX_BAND_5G_CHANNEL_NUM];
extern struct channel_info realtime_channel_info_5g[MAX_BAND_5G_CHANNEL_NUM];
extern time_t g_current_time;
extern sem_t g_semaphore;
extern int g_status;
extern pthread_mutex_t g_mutex,g_scan_schedule_mutex,g_finished_device_list_mutex;
extern int g_scan_schedule;
static struct ubus_context *ctx;
static struct ubus_subscriber rlog_event;
static struct blob_buf b;
struct user_input g_input;
int g_bw40_channel_num;
int g_bw80_channel_num;
int g_stream_num;
struct device_list g_finished_device_list;
struct device_list g_device_list;

static struct uloop_timeout retry;
static struct uloop_timeout status_timer;
struct scan_request
{
    struct ubus_request_data req;
    struct uloop_timeout timeout;
    int fd;
    int idx;
    char data[];
};

struct get_request
{
    struct ubus_request_data req;
    struct uloop_timeout timeout;
    int fd;
    int idx;
    char data[];
};
struct realtime_get_request
{
    struct ubus_request_data req;
    struct uloop_timeout timeout;
    int fd;
    int idx;
    char data[];
};
static const struct blobmsg_policy rlog_notify_policy[] = {
    [TOTAL] = {.name = "total", .type = BLOBMSG_TYPE_STRING},
    [CONFIG] = {.name = "config", .type = BLOBMSG_TYPE_ARRAY},
    [MODULE_DIR] = {.name = "module_dir", .type = BLOBMSG_TYPE_STRING},
    [TMP_DIR] = {.name = "tmp_dir", .type = BLOBMSG_TYPE_STRING},
    [TAR_DIR] = {.name = "tar_dir", .type = BLOBMSG_TYPE_STRING},
};
static const struct blobmsg_policy rlog_config_policy[] = {
    [NAME] = {.name = "name", .type = BLOBMSG_TYPE_STRING},
    [OPTION] = {.name = "option", .type = BLOBMSG_TYPE_STRING},
    [OLD_VALUE] = {.name = "old_value", .type = BLOBMSG_TYPE_STRING},
    [NEW_VALUE] = {.name = "new_value", .type = BLOBMSG_TYPE_STRING},
};

static const struct blobmsg_policy scan_policy[] = {
    [BAND] = {.name = "band", .type = BLOBMSG_TYPE_INT32},
    [CHANNEL_BITMAP] = {.name = "channel_bitmap", .type = BLOBMSG_TYPE_ARRAY},
    [SCAN_TIME] = {.name = "scan_time", .type = BLOBMSG_TYPE_INT32},
};

static const struct ubus_method channel_score_methods[] = {
    UBUS_METHOD_NOARG("get", get),
    UBUS_METHOD_NOARG("realtime_get", realtime_get),
    UBUS_METHOD("scan", scan, scan_policy),
};

static struct ubus_object_type channel_score_object_type =
    UBUS_OBJECT_TYPE("channel_score", channel_score_methods);

static struct ubus_object channel_score_object = {
    .name = "channel_score",
    .type = &channel_score_object_type,
    .methods = channel_score_methods,
    .n_methods = ARRAY_SIZE(channel_score_methods),
};

static struct ubus_subscriber test_event;

static void scan_reply(struct uloop_timeout *t)
{
    struct scan_request *req = container_of(t, struct scan_request, timeout);
    char temp[100];

    struct channel_info current_channel_info;

    blob_buf_init(&b, 0);

    spctrm_scn_wireless_channel_info(&current_channel_info, PLATFORM_5G);
    current_channel_info.score = spctrm_scn_wireless_channel_score(&current_channel_info);

    sprintf(temp,"%d",g_input.channel_num);
    blobmsg_add_string(&b, "total_channel",temp);

    sprintf(temp, "%d", current_channel_info.channel);
    blobmsg_add_string(&b, "current_channel", temp);

    sprintf(temp, "%d", current_channel_info.floornoise);
    blobmsg_add_string(&b, "floornoise", temp);

    sprintf(temp, "%d", current_channel_info.utilization);
    blobmsg_add_string(&b, "utilization", temp);

    sprintf(temp, "%f", current_channel_info.score);
    blobmsg_add_string(&b, "score", temp);

    blobmsg_add_string(&b, "status_code", req->data);

    ubus_send_reply(ctx, &req->req, b.head);

    ubus_complete_deferred_request(ctx, &req->req, 0);
    free(req);
}

static void realtime_get_reply(struct uloop_timeout *t)
{
    struct realtime_get_request *req = container_of(t, struct realtime_get_request, timeout);
    static struct blob_buf buf;
    char temp[512];
    int i;
    void *scan_list_obj;

    blob_buf_init(&buf, 0);

    spctrm_scn_dev_reset_stat(&g_device_list);
    /* find AP */
    i = spctrm_scn_dev_find_ap(&g_device_list);
    if (i == FAIL) {
        goto timeout;
    }
    memcpy(g_device_list.device[i].channel_info, realtime_channel_info_5g, sizeof(realtime_channel_info_5g));
    g_device_list.device[i].timestamp = time(NULL);
    g_device_list.device[i].input = g_input;
    g_device_list.device[i].status = g_status;
    g_device_list.device[i].finished_flag = FINISHED;

    add_timestamp_blobmsg(&buf, &g_current_time);

    spctrm_scn_tipc_send_get_msg(&g_device_list, 4);

    /* scan list*/
    scan_list_obj = blobmsg_open_array(&buf, "scan_list");

    for (i = 0; i < g_device_list.list_len; i++) {
        add_device_info_blobmsg(&buf, &g_device_list.device[i], true);
    }

    blobmsg_close_array(&buf, scan_list_obj);

    ubus_send_reply(ctx, &req->req, buf.head);
timeout:
    ubus_complete_deferred_request(ctx, &req->req, 0);
    free(req);
}

static void add_channel_score_blobmsg(struct blob_buf *buf, struct channel_info *channel_info)
{
    char temp[64];
    void *const channel_score_table = blobmsg_open_table(buf, NULL);

        sprintf(temp, "%d", channel_info->channel);
        blobmsg_add_string(buf, "channel", temp);
        memset(temp,0,sizeof(temp));
        if (spctrm_scn_wireless_check_channel_score(channel_info->score) != FAIL) {
            sprintf(temp, "%f", channel_info->score);
            blobmsg_add_string(buf, "score", temp);
            memset(temp,0,sizeof(temp));
            sprintf(temp, "%f", channel_info->rate);
            blobmsg_add_string(buf, "rate", temp);
        } else {
            blobmsg_add_string(buf, "score", "FAIL");
            blobmsg_add_string(buf, "rate", "FAIL");
        }
    
    blobmsg_close_table(buf, channel_score_table);
}

static void add_score_list_blobmsg(struct blob_buf *buf, int channel_num, struct channel_info *channel_info_list)
{
    int i;
    void *const score_list = blobmsg_open_array(buf, "score_list");
    struct device_info *p;
    int j;

    for (i = 0; i < channel_num; i++) {
        add_channel_score_blobmsg(buf, &channel_info_list[i]);
    }

    blobmsg_close_array(buf, score_list);
}

static void add_bw80_blobmsg(struct blob_buf *buf, struct device_info *device)
{
    void *bw80_table;
    uint8_t bw_bitmap;
    struct device_info *p;
    int j;

    if (spctrm_scn_wireless_get_country_channel_bwlist(&bw_bitmap) == FAIL) {
        return;
    }
    SPCTRM_SCN_DBG_FILE("\n%d",bw_bitmap);
    /* bw80 100 */
    if ((bw_bitmap & 4) != 4) {
        SPCTRM_SCN_DBG_FILE("\nno bw 80");
        return;
    }
    bw80_table = blobmsg_open_table(buf, "bw_80");

    list_for_each_device(p,j,&g_finished_device_list) {
        SPCTRM_SCN_DBG_FILE("SN %s \r\n",p->series_no);
    }
    spctrm_scn_wireless_bw80_channel_score(device);
    add_score_list_blobmsg(buf, g_bw80_channel_num / 4, device->bw80_channel);

    list_for_each_device(p,j,&g_finished_device_list) {
        SPCTRM_SCN_DBG_FILE("SN %s \r\n",p->series_no);
    }

    blobmsg_close_table(buf, bw80_table);
}

static void add_bw40_blobmsg(struct blob_buf *buf, struct device_info *device)
{
    void * bw40_table;
    uint8_t bw_bitmap;
    struct device_info *p;
    int j;

    list_for_each_device(p,j,&g_finished_device_list) {
        SPCTRM_SCN_DBG_FILE("SN %s \r\n",p->series_no);
    }
    if (spctrm_scn_wireless_get_country_channel_bwlist(&bw_bitmap) == FAIL) {
        SPCTRM_SCN_DBG_FILE("\nFAIL");
        return;
    }
    list_for_each_device(p,j,&g_finished_device_list) {
        SPCTRM_SCN_DBG_FILE("SN %s \r\n",p->series_no);
    }

    SPCTRM_SCN_DBG_FILE("\n%d",bw_bitmap);
    /* bw40 10 */
    if ((bw_bitmap & 2) != 2) {
        SPCTRM_SCN_DBG_FILE("\nno bw 40");
        return;
    }
    SPCTRM_SCN_DBG_FILE("\nhas bw 40");
    bw40_table = blobmsg_open_table(buf, "bw_40");

    list_for_each_device(p,j,&g_finished_device_list) {
        SPCTRM_SCN_DBG_FILE("SN %s \r\n",p->series_no);
    }

    spctrm_scn_wireless_bw40_channel_score(device);

    list_for_each_device(p,j,&g_finished_device_list) {
        SPCTRM_SCN_DBG_FILE("SN %s \r\n",p->series_no);
    }

    add_score_list_blobmsg(buf, g_bw40_channel_num / 2, device->bw40_channel);
    blobmsg_close_table(buf, bw40_table);
}

static void add_device_info_blobmsg(struct blob_buf *buf, struct device_info *device, int is_real_time)
{
    void *const device_obj = blobmsg_open_table(buf, NULL);
    void *BAND_5G_obj;
    void *bw20_table;
    char temp[128];
    struct device_info *p;
    int j;

    SPCTRM_SCN_DBG_FILE("\n %s \r\n", device->series_no);
    SPCTRM_SCN_DBG_FILE("\n %s \r\n", device->role);

    sprintf(temp,"%d",device->finished_flag);
    blobmsg_add_string(buf,"status",temp);
    blobmsg_add_string(buf, "SN", device->series_no);
    blobmsg_add_string(buf, "role", device->role);

    /* 5G */
    BAND_5G_obj = blobmsg_open_table(buf, "5G");

    bw20_table = blobmsg_open_table(buf, "bw_20");

    add_score_list_blobmsg(buf, g_input.channel_num, device->channel_info);
#ifdef ADD_CHANNEL_INFO_BLOB_MSG
    add_channel_info_blobmsg(buf,realtime_channel_info_5g,g_input.channel_num);
#endif
    blobmsg_close_table(buf, bw20_table);

    list_for_each_device(p,j,&g_finished_device_list) {
        SPCTRM_SCN_DBG_FILE("SN %s \r\n",p->series_no);
    }

    if (is_real_time == false) {
        add_bw40_blobmsg(buf, device);
        SPCTRM_SCN_DBG_FILE("\nadd bw40");
        add_bw80_blobmsg(buf, device);
        SPCTRM_SCN_DBG_FILE("\nadd bw80");
    }

    blobmsg_close_table(buf, BAND_5G_obj);
    blobmsg_close_table(buf, device_obj);
}

static void add_timestamp_blobmsg(struct blob_buf *buf, time_t *timestamp)
{
    char temp[256];
    sprintf(temp, "%ld", *timestamp);
    blobmsg_add_string(buf, "timestamp", temp);
}

static void add_channel_info_blobmsg(struct blob_buf *buf, struct channel_info *channel_info, int channel_num)
{
    char temp[512];
    int i = 0;
    void *obj;

    if (channel_info == NULL || buf == NULL) {
        return;
    }

    for (i = 0; i < channel_num; i++) {
        obj = blobmsg_open_table(buf, NULL);

        sprintf(temp, "%d", channel_info[i].channel);
        blobmsg_add_string(buf, "channel", temp);

        memset(temp,0,sizeof(temp));
        sprintf(temp, "%d", channel_info[i].floornoise);
        blobmsg_add_string(buf, "floornoise", temp);

        memset(temp,0,sizeof(temp));
        sprintf(temp, "%d", channel_info[i].utilization);
        blobmsg_add_string(buf, "utilization", temp);
        memset(temp,0,sizeof(temp));
        sprintf(temp, "%d", channel_info[i].bw);
        blobmsg_add_string(buf, "bw", temp);
        memset(temp,0,sizeof(temp));
        sprintf(temp, "%d", channel_info[i].obss_util);
        blobmsg_add_string(buf, "obss_util", temp);
        memset(temp,0,sizeof(temp));
        sprintf(temp, "%d", channel_info[i].tx_util);
        blobmsg_add_string(buf, "tx_util", temp);
        memset(temp,0,sizeof(temp));
        sprintf(temp, "%d", channel_info[i].rx_util);
        blobmsg_add_string(buf, "rx_util", temp);
        memset(temp,0,sizeof(temp));
        sprintf(temp, "%f", channel_info[i].score);/* 干扰得分 */
        blobmsg_add_string(buf, "score", temp);

        blobmsg_close_table(buf, obj);
    }
}

static void add_avg_score_list_blobmsg(struct blob_buf *buf,struct device_list *list)
{
    int j;
    int i,devices_num;
    char temp[256];
    struct device_info *p;
    double channel_avg_score[MAX_BAND_5G_CHANNEL_NUM],channel_avg_rate[MAX_BAND_5G_CHANNEL_NUM];
    void *avg_score_table_obj;
    void *bw20_list_obj,*bw40_list_obj,*bw80_list_obj;
    void *avg_score_elem_obj;
    uint8_t bw_bitmap;

    if (spctrm_scn_wireless_get_country_channel_bwlist(&bw_bitmap) == FAIL) {
        SPCTRM_SCN_DBG_FILE("\nFAIL");
        return;
    }
    SPCTRM_SCN_DBG_FILE("\n%d",bw_bitmap);

    memset(channel_avg_score, 0, MAX_BAND_5G_CHANNEL_NUM * sizeof(double));
    memset(channel_avg_rate, 0, MAX_BAND_5G_CHANNEL_NUM * sizeof(double));
    avg_score_table_obj = blobmsg_open_table(buf, "avg_score_table");

    bw20_list_obj = blobmsg_open_array(buf,"bw20");

    for (j = 0; j < g_input.channel_num; j++) {
        devices_num = 0;
        list_for_each_device(p, i, list) {
            SPCTRM_SCN_DBG_FILE("\np->finished_flag %d\n",p->finished_flag);
            if (p->finished_flag == FINISHED) {
                devices_num++;
                channel_avg_score[j] += p->channel_info[j].score;
                channel_avg_rate[j] += p->channel_info[j].rate;
                SPCTRM_SCN_DBG_FILE("\n rate  %f", p->channel_info[j].rate);
                SPCTRM_SCN_DBG_FILE("\n channel_avg_rate  %f", channel_avg_rate[j]);
                SPCTRM_SCN_DBG_FILE("\nscore  %f", p->channel_info[j].score);
            }
        }
        SPCTRM_SCN_DBG_FILE("\nans  %f", channel_avg_score[j]);

        SPCTRM_SCN_DBG_FILE("\n channel_avg_rate  %f", channel_avg_rate[j]);
        if (devices_num == 0) {
            devices_num = 1;
        }
        channel_avg_score[j] /= devices_num;
        channel_avg_rate[j] /=  (double)devices_num;
        SPCTRM_SCN_DBG_FILE("\n avg rate  %f", channel_avg_rate[j]);
        avg_score_elem_obj = blobmsg_open_table(buf,NULL);
        p = spctrm_scn_dev_find_ap2(list);
        memset(temp,0,sizeof(temp));
        sprintf(temp,"%d",p->channel_info[j].channel);
        blobmsg_add_string(buf,"channel",temp);
        memset(temp,0,sizeof(temp));
        if (spctrm_scn_wireless_check_channel_score(channel_avg_score[j]) != FAIL) {
            sprintf(temp,"%f",channel_avg_score[j]);/* 干扰得分 */
            blobmsg_add_string(buf,"avg_score",temp);

            memset(temp,0,sizeof(temp));
            sprintf(temp,"%f",channel_avg_rate[j]);
            blobmsg_add_string(buf,"avg_rate",temp);
        } else {
            blobmsg_add_string(buf,"avg_score","FAIL");
            blobmsg_add_string(buf,"avg_rate","FAIL");
        }

        blobmsg_close_table(buf,avg_score_elem_obj);
        avg_score_elem_obj = NULL;
    }
    SPCTRM_SCN_DBG_FILE("\n");
    blobmsg_close_array(buf,bw20_list_obj);
    SPCTRM_SCN_DBG_FILE("\n");
    /* bw40 10 */
    if ((bw_bitmap & 2) == 2) {
        bw40_list_obj = blobmsg_open_array(buf,"bw40");
        memset(channel_avg_score,0,sizeof(channel_avg_score));
        memset(channel_avg_rate,0,sizeof(channel_avg_rate));
        for (j = 0; j < g_bw40_channel_num / 2; j++) {
            list_for_each_device(p, i, list) {
                if (p->finished_flag == FINISHED) {
                    channel_avg_score[j] += p->bw40_channel[j].score;
                    channel_avg_rate[j] +=  p->bw40_channel[j].rate;
                    SPCTRM_SCN_DBG_FILE("\n rate  %f", p->channel_info[j].rate);
                    SPCTRM_SCN_DBG_FILE("\nscore  %f", p->bw40_channel[j].score);
                }
            }
            SPCTRM_SCN_DBG_FILE("\nchannel %d", p->bw40_channel[j].channel);
            SPCTRM_SCN_DBG_FILE("\nans  %f", channel_avg_score[j]);
            if (devices_num == 0) {
                devices_num = 1;
            }
            channel_avg_score[j] /= devices_num;
            channel_avg_rate[j] /= devices_num;
            avg_score_elem_obj = blobmsg_open_table(buf,NULL);
            p = spctrm_scn_dev_find_ap2(list);
            memset(temp,0,sizeof(temp));
            sprintf(temp,"%d",p->bw40_channel[j].channel);
            blobmsg_add_string(buf,"channel",temp);

            memset(temp,0,sizeof(temp));
            if (spctrm_scn_wireless_check_channel_score(channel_avg_score[j]) != FAIL) {
                sprintf(temp,"%f",channel_avg_score[j]);
                blobmsg_add_string(buf,"avg_score",temp);

                memset(temp,0,sizeof(temp));
                sprintf(temp,"%f",channel_avg_rate[j]);
                blobmsg_add_string(buf,"avg_rate",temp);
            } else {
                blobmsg_add_string(buf,"avg_score","FAIL");
                blobmsg_add_string(buf,"avg_rate","FAIL");
            }
            blobmsg_close_table(buf,avg_score_elem_obj);

            avg_score_elem_obj = NULL;
        }
        blobmsg_close_array(buf,bw40_list_obj);
    }

    if ((bw_bitmap & 4) == 4) {
        bw80_list_obj = blobmsg_open_array(buf,"bw80");
        memset(channel_avg_score,0,sizeof(channel_avg_score));
        memset(channel_avg_rate,0,sizeof(channel_avg_rate));
        for (j = 0; j < g_bw80_channel_num / 4; j++) {
            list_for_each_device(p, i, list) {
                if (p->finished_flag == FINISHED) {
                    channel_avg_score[j] += p->bw80_channel[j].score;
                    channel_avg_rate[j] +=  p->bw80_channel[j].rate;
                    SPCTRM_SCN_DBG_FILE("\nscore  %f", p->bw80_channel[j].score);
                }
            }
            SPCTRM_SCN_DBG_FILE("\nchannel %d", p->bw80_channel[j].channel);
            SPCTRM_SCN_DBG_FILE("\nans  %f", channel_avg_score[j]);
            if (devices_num == 0) {
                devices_num = 1;
            }
            channel_avg_score[j] /= devices_num;
            channel_avg_rate[j] /= devices_num;
            avg_score_elem_obj = blobmsg_open_table(buf,NULL);
            p = spctrm_scn_dev_find_ap2(list);
            memset(temp,0,sizeof(temp));
            sprintf(temp,"%d",p->bw80_channel[j].channel);
            blobmsg_add_string(buf,"channel",temp);
            if (spctrm_scn_wireless_check_channel_score(channel_avg_score[j]) != FAIL) {
                memset(temp,0,sizeof(temp));
                sprintf(temp,"%f",channel_avg_score[j]);
                blobmsg_add_string(buf,"avg_score",temp);

                memset(temp,0,sizeof(temp));
                sprintf(temp,"%f",channel_avg_rate[j]);
                blobmsg_add_string(buf,"avg_rate",temp);
            } else {
                blobmsg_add_string(buf,"avg_score","FAIL");
                blobmsg_add_string(buf,"avg_rate","FAIL");
            }


            blobmsg_close_table(buf,avg_score_elem_obj);
            avg_score_elem_obj = NULL;
        }
        blobmsg_close_array(buf,bw80_list_obj);
    }

    SPCTRM_SCN_DBG_FILE("\n");
    blobmsg_close_table(buf,avg_score_table_obj);

}

static void add_bw20_best_channel_blobmsg(struct blob_buf *buf, struct device_list *list)
{
    void *const bw20_table = blobmsg_open_table(buf, "bw_20");
    int best_channel_ptr;
    struct channel_info bw20_channel[MAX_BAND_5G_CHANNEL_NUM];
    int j, i;
    double channel_avg_score[MAX_BAND_5G_CHANNEL_NUM];
    char temp[100];
    struct device_info *p;
    int device_num;

    SPCTRM_SCN_DBG_FILE("\n");
    memset(channel_avg_score, 0, MAX_BAND_5G_CHANNEL_NUM * sizeof(double));
    SPCTRM_SCN_DBG_FILE("\n");
    for (j = 0; j < g_input.channel_num; j++) {
        device_num = 0;
        list_for_each_device(p, i, list) {
            if (p->finished_flag == FINISHED) {
                device_num++;
                channel_avg_score[j] += p->channel_info[j].score;
                SPCTRM_SCN_DBG_FILE("\nchannel %d", p->channel_info[j].channel);
                SPCTRM_SCN_DBG_FILE("\nscore  %f", p->channel_info[j].score);/* 干扰得分 */
            }
        }
        SPCTRM_SCN_DBG_FILE("\nans  %f", channel_avg_score[j]);
        if (device_num == 0) {
            device_num = 1;
        }
        channel_avg_score[j] /= device_num;
        SPCTRM_SCN_DBG_FILE("\nlist->list_len %d", list->list_len);
        SPCTRM_SCN_DBG_FILE("\nchannel_avg_score %f", channel_avg_score[j]);
    }

    best_channel_ptr = 0;
    for (i = 0; i < g_input.channel_num; i++) {
        if (spctrm_scn_wireless_check_channel_score(channel_avg_score[i]) != FAIL) {
            if (channel_avg_score[best_channel_ptr] < channel_avg_score[i]) {
                best_channel_ptr = i;
            }
        }
    }
    SPCTRM_SCN_DBG_FILE("\nbest_channel_ptr %d", best_channel_ptr);

    sprintf(temp, "%f", channel_avg_score[best_channel_ptr]);
    blobmsg_add_string(buf, "score", temp);
    SPCTRM_SCN_DBG_FILE("\nbest_score %f", channel_avg_score[best_channel_ptr]);
    memset(temp,0,sizeof(temp));
    sprintf(temp, "%d", g_channel_info_5g[best_channel_ptr].channel);
    blobmsg_add_string(buf, "channel", temp);
    SPCTRM_SCN_DBG_FILE("\nchannel %d", g_channel_info_5g[best_channel_ptr].channel);

    blobmsg_close_table(buf, bw20_table);
}

static void add_bw40_best_channel_blobmsg(struct blob_buf *buf, struct device_list *list)
{
    void *bw40_table;
    int best_channel_ptr;
    int j, i;
    int device_num;
    double channel_avg_score[MAX_BAND_5G_CHANNEL_NUM];
    char temp[100];
    struct device_info *p;
    uint8_t bw_bitmap;

    if (spctrm_scn_wireless_get_country_channel_bwlist(&bw_bitmap) == FAIL) {
        SPCTRM_SCN_DBG_FILE("\nFAIL");
        return;
    }
    SPCTRM_SCN_DBG_FILE("\n%d",bw_bitmap);
    /* bw40 10 */
    if ((bw_bitmap & 2) != 2) {
        SPCTRM_SCN_DBG_FILE("\nno bw 40");
        return;
    }
    SPCTRM_SCN_DBG_FILE("\nhas bw 40");

    bw40_table = blobmsg_open_table(buf, "bw_40");
    memset(channel_avg_score, 0, MAX_BAND_5G_CHANNEL_NUM * sizeof(double));

    for (j = 0; j < g_input.channel_num / 2; j++) {
        device_num = 0;
        list_for_each_device(p, i, list) {
            if (p->finished_flag == FINISHED) {
                device_num++;
                channel_avg_score[j] += p->bw40_channel[j].score;
            }

        }
      SPCTRM_SCN_DBG_FILE("\nlist->list_len %d",list->list_len);
        if (device_num == 0) {
            device_num = 1;
        }
        channel_avg_score[j] /= device_num;
    }

    best_channel_ptr = 0;
    SPCTRM_SCN_DBG_FILE("\ng_input.channel_num %d",g_input.channel_num);
    for (i = 0; i < g_bw40_channel_num / 2; i++) {
        if (spctrm_scn_wireless_check_channel_score(channel_avg_score[i]) != FAIL) {
            if (channel_avg_score[best_channel_ptr] < channel_avg_score[i]) {
                best_channel_ptr = i;
            }
        }
    }
    SPCTRM_SCN_DBG_FILE("\nbest_channel_ptr %d", best_channel_ptr);
    memset(temp,0,sizeof(temp));
    sprintf(temp, "%f", channel_avg_score[best_channel_ptr]);
    blobmsg_add_string(buf, "score", temp);
    memset(temp,0,sizeof(temp));
    p = spctrm_scn_dev_find_ap2(list);
    sprintf(temp, "%d",p->bw40_channel[best_channel_ptr].channel);
    blobmsg_add_string(buf, "channel", temp);

    blobmsg_close_table(buf, bw40_table);
}

static void add_bw80_best_channel_blobmsg(struct blob_buf *buf, struct device_list *list)
{
    void * bw80_table;
    int best_channel_ptr;
    struct channel_info bw80_channel[9]; /* MAX_BAND_5G_CHANNEL_NUM / 4 */
    int j, i;
    double channel_avg_score[MAX_BAND_5G_CHANNEL_NUM];
    char temp[100];
    struct device_info *p;
    int device_num;
    uint8_t bw_bitmap;

    if (spctrm_scn_wireless_get_country_channel_bwlist(&bw_bitmap) == FAIL) {
        SPCTRM_SCN_DBG_FILE("\nFAIL");
        return;
    }
    SPCTRM_SCN_DBG_FILE("\n%d",bw_bitmap);
    /* bw40 10 */
    if ((bw_bitmap & 4) != 4) {
        SPCTRM_SCN_DBG_FILE("\nno bw 80");
        return;
    }
    SPCTRM_SCN_DBG_FILE("\nhas bw 80");
    bw80_table = blobmsg_open_table(buf, "bw_80");
    memset(channel_avg_score, 0, MAX_BAND_5G_CHANNEL_NUM * sizeof(double));

    for (j = 0; j < g_bw80_channel_num / 4; j++) {
        device_num = 0;
        list_for_each_device(p, i, list) {
            if (p->finished_flag == FINISHED) {
                device_num++;
                channel_avg_score[j] += p->bw80_channel[j].score;
            }

        }
        if (device_num == 0) {
            device_num = 1;
        }
        channel_avg_score[j] /= device_num;
    }

    best_channel_ptr = 0;
    for (i = 0; i < g_bw80_channel_num / 4; i++) {
        if (spctrm_scn_wireless_check_channel_score(channel_avg_score[i]) != FAIL) {
            if (channel_avg_score[best_channel_ptr] < channel_avg_score[i]) {
                best_channel_ptr = i;
            }
        }
    }
    SPCTRM_SCN_DBG_FILE("\nbest_channel_ptr %d", best_channel_ptr);
    sprintf(temp, "%f", channel_avg_score[best_channel_ptr]);
    blobmsg_add_string(buf, "score", temp);
    SPCTRM_SCN_DBG_FILE("\n");
    p = spctrm_scn_dev_find_ap2(list);
    SPCTRM_SCN_DBG_FILE("\n");
    sprintf(temp, "%d",p->bw80_channel[best_channel_ptr].channel);
    SPCTRM_SCN_DBG_FILE("\n");
    blobmsg_add_string(buf, "channel", temp);

    blobmsg_close_table(buf, bw80_table);
}

static void get_reply(struct uloop_timeout *t)
{
    struct channel_info current_channel_info;
    struct get_request *req = container_of(t, struct get_request, timeout);
    static struct blob_buf buf;
    struct device_info *p;
    char temp[512];
    int i,j;
    int code;
    void *best_channel_obj;
    void *scan_list_obj;

    SPCTRM_SCN_DBG_FILE("\n");

    blob_buf_init(&buf, 0);

    if (g_status == SCAN_BUSY) {
        goto scan_busy;
    }

    if (g_status == SCAN_NOT_START) {
        SPCTRM_SCN_DBG_FILE("\nscan not start");
        goto scan_not_start;
    }

    /* find AP */
    i = spctrm_scn_dev_find_ap(&g_finished_device_list);
    if (i == FAIL) {

        goto error;
    }

    list_for_each_device(p,j,&g_finished_device_list) {
        SPCTRM_SCN_DBG_FILE("SN %s \r\n",p->series_no);
    }

    pthread_mutex_lock(&g_finished_device_list_mutex);
    memcpy(g_finished_device_list.device[i].channel_info, g_channel_info_5g, sizeof(g_channel_info_5g));
    for (j = 0;j < g_input.channel_num;j++) {
        SPCTRM_SCN_DBG_FILE("rate %f \r\n",g_finished_device_list.device[i].channel_info[j].rate);
        spctrm_scn_wireless_rate_filter(&(g_finished_device_list.device[i]),&(g_finished_device_list.device[i].channel_info[j].rate));
    }
    g_finished_device_list.device[i].timestamp = g_current_time;
    g_finished_device_list.device[i].input = g_input;
    g_finished_device_list.device[i].status = g_status;
    
    pthread_mutex_unlock(&g_finished_device_list_mutex);

    blobmsg_add_string(&buf, "status", "idle");
    blobmsg_add_string(&buf, "status_code", "2");

    add_timestamp_blobmsg(&buf, &g_current_time);
    SPCTRM_SCN_DBG_FILE("\ng_finished_device_list.list_len %d", g_finished_device_list.list_len);
    /* scan list*/
    scan_list_obj = blobmsg_open_array(&buf, "scan_list");

    list_for_each_device(p,j,&g_finished_device_list) {
        SPCTRM_SCN_DBG_FILE("SN %s \r\n",p->series_no);
    }

    list_for_each_device(p,j,&g_finished_device_list) {
        add_device_info_blobmsg(&buf,p,false);
    }
    // for (i = 0; i < g_finished_device_list.list_len; i++) {
    //     add_device_info_blobmsg(&buf, &g_finished_device_list.device[i], false);
    // }

    blobmsg_close_array(&buf, scan_list_obj);

    /* best channel*/
    best_channel_obj = blobmsg_open_table(&buf, "best_channel");
    add_bw20_best_channel_blobmsg(&buf, &g_finished_device_list);
    add_bw40_best_channel_blobmsg(&buf, &g_finished_device_list);
    add_bw80_best_channel_blobmsg(&buf, &g_finished_device_list);
    SPCTRM_SCN_DBG_FILE("\n");
    blobmsg_close_table(&buf, best_channel_obj);

    /* avg score channel list*/
    add_avg_score_list_blobmsg(&buf,&g_finished_device_list);
    ubus_send_reply(ctx, &req->req, buf.head);

    ubus_complete_deferred_request(ctx, &req->req, 0);

    free(req);
    return;

scan_not_start:

    blobmsg_add_string(&buf, "status", "not start");
    blobmsg_add_string(&buf, "status_code", "0");

    ubus_send_reply(ctx, &req->req, buf.head);

    ubus_complete_deferred_request(ctx, &req->req, 0);

    free(req);
    return;

scan_timeout:
    blobmsg_add_string(&buf, "status", "timeout");
    blobmsg_add_string(&buf, "status_code", "3");

    spctrm_scn_wireless_channel_info(&current_channel_info, PLATFORM_5G);
    current_channel_info.score = spctrm_scn_wireless_channel_score(&current_channel_info);
    memset(temp,0,sizeof(temp));
    sprintf(temp,"%d",current_channel_info.channel);
    blobmsg_add_string(&buf, "current_scan_channel", temp);

    ubus_send_reply(ctx, &req->req, buf.head);
    ubus_complete_deferred_request(ctx, &req->req, 0);

    free(req);
    return;

scan_busy:
    blobmsg_add_string(&buf, "status", "busy");
    blobmsg_add_string(&buf, "status_code", "1");

    spctrm_scn_wireless_channel_info(&current_channel_info, PLATFORM_5G);
    current_channel_info.score = spctrm_scn_wireless_channel_score(&current_channel_info);

    pthread_mutex_lock(&g_scan_schedule_mutex);
    sprintf(temp,"%d",g_scan_schedule);
    pthread_mutex_unlock(&g_scan_schedule_mutex);

    blobmsg_add_string(&buf, "scan_schedule", temp);

    sprintf(temp,"%d",g_input.channel_num);
    blobmsg_add_string(&buf, "total_channel", temp);
    ubus_send_reply(ctx, &req->req, buf.head);
    ubus_complete_deferred_request(ctx, &req->req, 0);
error:
    free(req);
}

static int scan(struct ubus_context *ctx, struct ubus_object *obj,
                struct ubus_request_data *req, const char *method,
                struct blob_attr *msg)
{
    struct channel_info channel_info;
    struct scan_request *hreq;
    size_t len;
    struct blob_attr *tb[__SCAN_MAX];
    char format[100];
    struct blob_attr *channel_bitmap_array[MAX_CHANNEL_NUM];
    static struct blobmsg_policy channel_bitmap_policy[MAX_CHANNEL_NUM];
    int i,j,total_band_num;
    char msgstr[100];
    uint64_t bitmap_2G, bitmap_5G;
    struct device_info *p;

    for (i = 0; i < MAX_CHANNEL_NUM; i++) {
        channel_bitmap_policy[i].type = BLOBMSG_TYPE_INT32;
    }

    bitmap_5G = 0;
    bitmap_2G = 0;

    blobmsg_parse(scan_policy, ARRAY_SIZE(scan_policy), tb, blob_data(msg), blob_len(msg));

    SPCTRM_SCN_DBG_FILE("g_status %d \r\n",g_status);
    if (g_status == SCAN_BUSY) {
        len = sizeof(*hreq) + sizeof(msgstr) + 1;
        hreq = calloc(1, len);
        if (!hreq) {
            return UBUS_STATUS_UNKNOWN_ERROR;
        }
        sprintf(hreq->data, "%d", FAIL);
        goto error;
    }

    if (tb[BAND]) {
        SPCTRM_SCN_DBG_FILE("g_status %d \r\n", g_status);
        if (blobmsg_get_u32(tb[BAND]) != PLATFORM_5G && blobmsg_get_u32(tb[BAND]) != PLATFORM_2G) {
            len = sizeof(*hreq) + sizeof(msgstr) + 1;
            hreq = calloc(1, len);
            if (!hreq) {
                return UBUS_STATUS_UNKNOWN_ERROR;
            }
            sprintf(hreq->data, "%d", FAIL);
            goto error;
        }

        spctrm_scn_wireless_channel_info(&channel_info, blobmsg_get_u32(tb[BAND]));

        g_bw40_channel_num = spctrm_scn_wireless_country_channel(BW_40,&bitmap_2G,&bitmap_5G,PLATFORM_5G);
        g_bw80_channel_num = spctrm_scn_wireless_country_channel(BW_80,&bitmap_2G,&bitmap_5G,PLATFORM_5G);
        total_band_num = spctrm_scn_wireless_country_channel(BW_20, &bitmap_2G, &bitmap_5G, PLATFORM_5G);

        if (total_band_num == FAIL) {
            len = sizeof(*hreq) + sizeof(msgstr) + 1;
            hreq = calloc(1, len);
            if (!hreq) {
                return UBUS_STATUS_UNKNOWN_ERROR;
            }
            sprintf(hreq->data, "%d", FAIL);
            goto error;
        }
        g_input.band = blobmsg_get_u32(tb[BAND]);

        if (tb[SCAN_TIME]) {
            g_input.scan_time = blobmsg_get_u32(tb[SCAN_TIME]);
        }

        if (tb[CHANNEL_BITMAP] && blobmsg_check_array(tb[CHANNEL_BITMAP], BLOBMSG_TYPE_INT32)) {
            g_input.channel_num = blobmsg_check_array(tb[CHANNEL_BITMAP], BLOBMSG_TYPE_INT32);
            g_input.channel_bitmap = 0;
            blobmsg_parse_array(channel_bitmap_policy, ARRAY_SIZE(channel_bitmap_policy), channel_bitmap_array, blobmsg_data(tb[CHANNEL_BITMAP]), blobmsg_len(tb[CHANNEL_BITMAP]));
            for (i = 0; i < g_input.channel_num; i++) {
                if (spctrm_scn_wireless_channel_check(blobmsg_get_u32(channel_bitmap_array[i])) == FAIL) {
                    len = sizeof(*hreq) + sizeof(msgstr) + 1;
                    hreq = calloc(1, len);
                    if (!hreq) {
                        return UBUS_STATUS_UNKNOWN_ERROR;
                    }
                    sprintf(hreq->data, "%d", FAIL);
                    goto error;
                }
                g_input.channel_bitmap |= 1 << (blobmsg_get_u32(channel_bitmap_array[i]) / 4 - 9);
            }
            if ((g_input.channel_bitmap & bitmap_5G) != g_input.channel_bitmap) {
                len = sizeof(*hreq) + sizeof(msgstr) + 1;
                hreq = calloc(1, len);
                if (!hreq) {
                    return UBUS_STATUS_UNKNOWN_ERROR;
                }
                sprintf(hreq->data, "%d", FAIL);
                goto error;
            }
        }
        else {
            g_input.channel_bitmap = bitmap_5G;
            g_input.channel_num = total_band_num;
        }
        len = sizeof(*hreq) + sizeof(format) + 1;
        hreq = calloc(1, len);
        if (!hreq) {
            return UBUS_STATUS_UNKNOWN_ERROR;
        }
        sprintf(hreq->data, "%d", SUCCESS);

        pthread_mutex_lock(&g_finished_device_list_mutex);
        memset(&g_finished_device_list, 0, sizeof(g_finished_device_list));
        if (spctrm_scn_dev_wds_list(&g_finished_device_list) == FAIL) {
            len = sizeof(*hreq) + sizeof(msgstr) + 1;
            hreq = calloc(1, len);
            if (!hreq) {
                return UBUS_STATUS_UNKNOWN_ERROR;
            }
            sprintf(hreq->data, "{\"code\":%d}", FAIL);
            pthread_mutex_unlock(&g_finished_device_list_mutex);
            goto error;
        }

        if (g_finished_device_list.list_len == 1) {
            g_stream_num = g_finished_device_list.list_len;
        } else {
            g_stream_num = g_finished_device_list.list_len - 1;
        }

        SPCTRM_SCN_DBG_FILE("g_stream_num %d",g_stream_num);
        pthread_mutex_unlock(&g_finished_device_list_mutex);
        g_scan_schedule = 0;
        pthread_mutex_lock(&g_mutex);
        memset(&g_device_list, 0, sizeof(g_device_list));
        if (spctrm_scn_dev_wds_list(&g_device_list) == FAIL) {
            len = sizeof(*hreq) + sizeof(msgstr) + 1;
            hreq = calloc(1, len);
            if (!hreq) {
                return UBUS_STATUS_UNKNOWN_ERROR;
            }
            sprintf(hreq->data, "{\"code\":%d}", FAIL);
            pthread_mutex_unlock(&g_mutex);
            goto error;
        }
        
        g_status = SCAN_BUSY;
        pthread_mutex_unlock(&g_mutex);


        pthread_mutex_lock(&g_finished_device_list_mutex);
        /* timestamp */
        g_current_time = time(NULL);
        if (spctrm_scn_tipc_send_start_msg(&g_finished_device_list, 1000) == FAIL) {
            pthread_mutex_unlock(&g_finished_device_list_mutex);
            len = sizeof(*hreq) + sizeof(msgstr) + 1;
            hreq = calloc(1, len);
            if (!hreq) {
                return UBUS_STATUS_UNKNOWN_ERROR;
            }
            sprintf(hreq->data, "{\"code\":%d}", FAIL);
            goto error;
        }
        pthread_mutex_unlock(&g_finished_device_list_mutex);

        sem_post(&g_semaphore);

    } else {
        len = sizeof(*hreq) + sizeof(msgstr) + 1;
        hreq = calloc(1, len);
        if (!hreq) {
            return UBUS_STATUS_UNKNOWN_ERROR;
        }
        sprintf(hreq->data, "{\"code\":%d}", FAIL);
        goto error;
    }
error:
    ubus_defer_request(ctx, req, &hreq->req);
    hreq->timeout.cb = scan_reply;
    uloop_timeout_set(&hreq->timeout, 1000);
    return 0;

}

static int realtime_get(struct ubus_context *ctx, struct ubus_object *obj,
                        struct ubus_request_data *req, const char *method,
                        struct blob_attr *msg)
{
    struct realtime_get_request *hreq;
    char format[100];
    const char *msgstr = "(error)";
    size_t len = sizeof(*hreq) + sizeof(format) + strlen(obj->name) + strlen(msgstr) + 1;

    hreq = calloc(1, len);
    if (!hreq) {
        return UBUS_STATUS_UNKNOWN_ERROR;
    }

    ubus_defer_request(ctx, req, &hreq->req);
    hreq->timeout.cb = realtime_get_reply;
    uloop_timeout_set(&hreq->timeout, 1000);/* 1s后执行回调 */

    return 0;
}

static int get(struct ubus_context *ctx, struct ubus_object *obj,
               struct ubus_request_data *req, const char *method,
               struct blob_attr *msg)
{
    struct get_request *hreq;
    char format[100];
    const char *msgstr = "(error)";
    size_t len = sizeof(*hreq) + sizeof(format) + strlen(obj->name) + strlen(msgstr) + 1;

    hreq = calloc(1, len);
    if (!hreq) {
        return UBUS_STATUS_UNKNOWN_ERROR;
    }

    ubus_defer_request(ctx, req, &hreq->req);
    hreq->timeout.cb = get_reply;
    uloop_timeout_set(&hreq->timeout, 1000); /* 1s后执行回调 */

    return 0;
}

static void mode_switch_notify(struct ubus_context *ctx, struct ubus_event_handler *ev,
                     const char *type, struct blob_attr *msg)
{
    system("rm /etc/spectrum_scan_cache");
    system("/etc/init.d/spectrum_scan restart");
}

static int test_notify(struct ubus_context *ctx, struct ubus_object *obj,
            struct ubus_request_data *req, const char *method,
            struct blob_attr *msg)
{
    static struct blobmsg_policy *config_array_policy;
    struct blob_attr *tb[__RLOG_NOTIFY_MAX];
    struct blob_attr *config_tb[__RLOG_CONFIG_MAX];
    struct blob_attr *config_array[1024];
    int i,total,ret;
    char *strbuf;

    SPCTRM_SCN_DBG_FILE("rlog ubus notify\r\n");
    blobmsg_parse(rlog_notify_policy, ARRAY_SIZE(rlog_notify_policy),tb, blob_data(msg), blob_len(msg));

    if (tb[TOTAL] || tb[CONFIG] == NULL) {
        return UBUS_STATUS_UNKNOWN_ERROR;
    }
    total = atoi(blobmsg_get_string(tb[TOTAL]));
    SPCTRM_SCN_DBG_FILE("total %d\r\n",total);
    config_array_policy = (struct blobmsg_policy*)malloc(total * sizeof(struct blobmsg_policy));
    if (config_array_policy == NULL) {
        return UBUS_STATUS_UNKNOWN_ERROR;
    }

    for (i = 0; i < total; i++) {
        config_array_policy[i].type = BLOBMSG_TYPE_TABLE;
    }

    blobmsg_parse_array(config_array_policy, total, config_array, blobmsg_data(tb[CONFIG]), blobmsg_len(tb[CONFIG]));
    strbuf = blobmsg_format_json(tb[CONFIG],true);
    if (strbuf == NULL) {
        free(config_array_policy);
        return UBUS_STATUS_UNKNOWN_ERROR;
    }
    SPCTRM_SCN_DBG_FILE("%s",strbuf);
    for (i = 0 ;i < total;i++) {
        blobmsg_parse(rlog_config_policy,ARRAY_SIZE(rlog_config_policy),config_tb,blobmsg_data(config_array[i]),blobmsg_len(config_array[i]));
        SPCTRM_SCN_DBG_FILE("%s\r\n",blobmsg_get_string(config_tb[NAME]));
        SPCTRM_SCN_DBG_FILE("%s\r\n",blobmsg_get_string(config_tb[OPTION]));
        SPCTRM_SCN_DBG_FILE("%s\r\n",blobmsg_get_string(config_tb[OLD_VALUE]));
        SPCTRM_SCN_DBG_FILE("%s\r\n",blobmsg_get_string(config_tb[NEW_VALUE]));

        if (strcmp(blobmsg_get_string(config_tb[NAME]),"spectrumScan") == 0) {
        }
    }
    free(strbuf);
    free(config_array_policy);
    
    return UBUS_STATUS_OK;
}

struct ubus_event_handler mode_switch_event;
static void server_main(void)
{
    int ret;
    uint32_t id;
    struct ubus_object *dbg_obj;

    if (g_mode == AP_MODE) {
        ret = ubus_add_object(ctx, &channel_score_object);
        if (ret) {
            fprintf(stderr, "Failed to add object: %s\n", ubus_strerror(ret));
            return;
        }
    }

    dbg_obj = dbg_get_ubus_object();
    if (dbg_obj == NULL) {
        return;
    }

    if (ubus_add_object(ctx, dbg_obj)) {
        return;
    }

    ret = ubus_register_subscriber(ctx, &test_event);
    if (ret != UBUS_STATUS_OK) {
        SPCTRM_SCN_DBG_FILE("\nerror");
        return;
    }
    test_event.cb = test_notify;

    if (ubus_lookup_id(ctx, "rlog", &id)) {
        fprintf(stderr, "Failed to look up rlog object\n");
        SPCTRM_SCN_DBG_FILE("\n not support rlog");
    } else {
        ret = ubus_subscribe(ctx, &test_event,id);
        if (ret != UBUS_STATUS_OK) {
            SPCTRM_SCN_DBG_FILE("\nerror");
            return;
        }
    }

    mode_switch_event.cb = mode_switch_notify;
    ubus_register_event_handler(ctx,&mode_switch_event,"notify");

    uloop_run();
}

static void spctrm_scn_ubus_reconnect_timer(struct uloop_timeout *t)
{
    if (ubus_reconnect(ctx,NULL) != UBUS_STATUS_OK) {
        uloop_timeout_set(&retry,1000);
        SPCTRM_SCN_DBG_FILE("\nretry");
        return;
    }
    SPCTRM_SCN_DBG_FILE("\nfinish  obj id %08x",ctx->local_id);
    ubus_add_uloop(ctx);

}

static void spctrm_scn_ubus_connection_lost(struct ubus_context *ctx)
{
    SPCTRM_SCN_DBG_FILE("\nconnection_lost");
    retry.cb = spctrm_scn_ubus_reconnect_timer;
    uloop_timeout_set(&retry,1000);
}

void spctrm_scn_ubus_thread()
{
    const char *ubus_socket = NULL;

    uloop_init();
    // signal(SIGPIPE, SIG_IGN);
    SPCTRM_SCN_DBG_FILE("\nubus start");
    ctx = ubus_connect(ubus_socket);
    if (!ctx) {
        fprintf(stderr, "Failed to connect to ubus\n");
        return;
    }

    ctx->connection_lost = spctrm_scn_ubus_connection_lost;
    ubus_add_uloop(ctx);

    server_main();

    ubus_free(ctx);
    uloop_done();
    SPCTRM_SCN_DBG_FILE("\nubus done");

}
