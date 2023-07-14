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

static int spctrm_scn_ubus_set(struct ubus_context *ctx, struct ubus_object *obj,
		      struct ubus_request_data *req, const char *method,
		      struct blob_attr *msg);
static int spctrm_scn_ubus_get(struct ubus_context *ctx, struct ubus_object *obj,
		      struct ubus_request_data *req, const char *method,
		      struct blob_attr *msg);
              
struct spctrm_scn_ubus_get_request
{
    struct ubus_request_data req;
    struct uloop_timeout timeout;
    int fd;
    int idx;
    char data[];
};

struct ubus_connect_ctx *ctx;
struct device_list g_device_list;
int8_t g_status;

static const struct blobmsg_policy spctrm_scn_ubus_set_policy[] = {
    [BAND] = {.name = "band", .type = BLOBMSG_TYPE_INT32},
    [CHANNEL_LIST] = {.name = "channel_list", .type = BLOBMSG_TYPE_ARRAY},
    [SCAN_TIME] = {.name = "scan_time", .type = BLOBMSG_TYPE_INT32},
};
static const struct ubus_method spctrm_scn_methods[] = {
    UBUS_METHOD_NOARG("get", spctrm_scn_ubus_get),
    UBUS_METHOD("set", spctrm_scn_ubus_set, spctrm_scn_ubus_set_policy),
};
static struct ubus_object_type spctrm_scn_object_type =
    UBUS_OBJECT_TYPE("spctrm_scn", spctrm_scn_methods);

static struct ubus_object spctrm_scn_object = {
    .name = "spctrm_scn",
    .type = &spctrm_scn_object_type,
    .methods = spctrm_scn_methods,
    .n_methods = ARRAY_SIZE(spctrm_scn_methods),
};
static void spctrm_scn_tipc_wait_cpe_cb(struct uloop_timeout *t) 
{
    struct spctrm_scn_ubus_set_request *hreq = container_of(t,struct spctrm_scn_ubus_set_request,timeout);
    struct device_info *p;
    int i;

    list_for_each_device(p,i,&g_device_list) {
        debug("");
        if (p->finished_flag != FINISHED) {
            debug("");
            uloop_timeout_set(&hreq->timeout,500);
            return;
        }
    }

    hreq->timeout.cb = spctrm_scn_wireless_scan_task;
    uloop_timeout_set(&hreq->timeout,1000);
    debug("");
    return;
    
}
static void spctrm_scn_ubus_set_reply(struct uloop_timeout *t) 
{ 
    char start_msg[9] = "start";
    struct spctrm_scn_ubus_set_request *hreq = container_of(t,struct spctrm_scn_ubus_set_request,timeout);
    
    debug("");
    
    ubus_complete_deferred_request(ctx,&hreq->req,0);

    if (spctrm_scn_tipc_send(SERVER_TYPE,PROTOCAL_TYPE_SCAN,sizeof(start_msg),start_msg) == FAIL) {
        free(hreq);

        debug("FAIL");
        return;
    }

    if (spctrm_scn_tipc_send(SERVER_TYPE,PROTOCAL_TYPE_SCAN,sizeof(start_msg),start_msg) == FAIL) {
        free(hreq);

        debug("FAIL");
        return;
    }
    
    debug("");
    hreq->timeout.cb = spctrm_scn_tipc_wait_cpe_cb;
    uloop_timeout_set(&hreq->timeout,500);
    
}

static int spctrm_scn_ubus_set(struct ubus_context *ctx, struct ubus_object *obj,
		      struct ubus_request_data *req, const char *method,
		      struct blob_attr *msg)
{
    struct spctrm_scn_ubus_set_request *hreq;
    size_t len;
    struct blob_attr *tb[__SCAN_MAX];
    struct blob_attr *channel_list_array[MAX_CHANNEL_NUM];
    static struct blobmsg_policy channel_list_policy[MAX_CHANNEL_NUM];
    int i;
    uint64_t band_5g_channel_bitmap,country_channel_bitmap;
    uint8_t band,channel_num,channel,bitset;
    struct device_info *p;

    for (i = 0; i < MAX_CHANNEL_NUM; i++) {
        channel_list_policy[i].type = BLOBMSG_TYPE_INT32;
    }

    blobmsg_parse(spctrm_scn_ubus_set_policy, ARRAY_SIZE(spctrm_scn_ubus_set_policy), tb, blob_data(msg), blob_len(msg));

    if (g_status == SCAN_BUSY) {
        goto error;
    }

    if (tb[BAND]) {
        band = blobmsg_get_u32(tb[BAND]);
        debug("band %d",band);
    } else {
        debug("band NULL");
        goto error;
    }

    if (band != BAND_5G && band != BAND_2G) {
        debug("band error");
        goto error;
    }

    if (spctrm_scn_wireless_country_channel(&country_channel_bitmap,&channel_num,BW_20,BAND_5G) == FAIL) {
        debug("");
        goto error;
    }

    len = sizeof(struct spctrm_scn_ubus_set_request);
	hreq = calloc(1, len);
    if (hreq == NULL) {
        return UBUS_STATUS_UNKNOWN_ERROR;
    }

    if (tb[CHANNEL_LIST]) {
        /* custom channel list */
        channel_num = blobmsg_check_array(tb[CHANNEL_LIST], BLOBMSG_TYPE_INT32);
        hreq->channel_bitmap = 0;
        blobmsg_parse_array(channel_list_policy, ARRAY_SIZE(channel_list_policy), channel_list_array, blobmsg_data(tb[CHANNEL_LIST]), blobmsg_len(tb[CHANNEL_LIST]));
        for (i = 0;i < channel_num;i++) {
            channel = blobmsg_get_u32(channel_list_array[i]);

            if (spctrm_scn_wireless_check_channel(channel) == FAIL) {
                free(hreq);
                goto error;
            }

            if (channel_to_bitset(channel,&bitset) == FAIL) {
                free(hreq);
                goto error;
            }
            debug("bitset %d",bitset);

            BITMAP_SET(hreq->channel_bitmap,bitset);
            
        }
        debug("hreq->channel_bitmap %lld",hreq->channel_bitmap);
    } else {
        /* default */
        hreq->channel_bitmap = country_channel_bitmap;
        debug("hreq->channel_bitmap %lld",hreq->channel_bitmap);
    }
    debug("");
    if (tb[SCAN_TIME]) {
        hreq->scan_time = blobmsg_get_u32(tb[SCAN_TIME]);
    } else {
        /* default */
        hreq->scan_time = 3;
    }

    if (spctrm_scn_dev_wds_list(&g_device_list) == FAIL) {
        free(hreq);
        return UBUS_STATUS_UNKNOWN_ERROR;
    }
    p = spctrm_scn_dev_find_ap(&g_device_list);

    if (p == NULL) {
        free(hreq);
        return UBUS_STATUS_UNKNOWN_ERROR;
    }
    
    memcpy(&hreq->device_info,p,sizeof(struct device_info));
    debug("");
    ubus_defer_request(ctx,req,&hreq->req);

    debug("");
    g_status = SCAN_BUSY;
    hreq->timeout.cb = spctrm_scn_ubus_set_reply;
    debug("");
    uloop_timeout_set(&hreq->timeout,1000);
    
error:
    return UBUS_STATUS_OK;
}
static void spctrm_scn_ubus_get_reply(struct uloop_timeout *t) {
    struct spctrm_scn_ubus_get_request *hreq = container_of(t,struct spctrm_scn_ubus_get_request,timeout);
    static struct blob_buf buf;

    blob_buf_init(&buf, 0);
    blobmsg_add_string(&buf,"test","123");
    ubus_send_reply(ctx,&hreq->req,buf.head);
    ubus_complete_deferred_request(ctx,&hreq->req,0);
    free(hreq);
}
static int spctrm_scn_ubus_get(struct ubus_context *ctx, struct ubus_object *obj,
						struct ubus_request_data *req, const char *method,
						struct blob_attr *msg)
{
	struct blob_attr *tb[__SCAN_MAX];
    struct spctrm_scn_ubus_get_request *hreq;
    size_t len;
    
    len = sizeof(struct spctrm_scn_ubus_get_request);
	hreq = calloc(1, len);
    if (hreq == NULL) {
        return UBUS_STATUS_UNKNOWN_ERROR;
    }

    ubus_defer_request(ctx,req,&hreq->req);

    hreq->timeout.cb = spctrm_scn_ubus_get_reply;

    uloop_timeout_set(&hreq->timeout,1000);

	return UBUS_STATUS_OK;
}

void spctrm_scn_ubus_task(void)
{
    const char *ubus_socket = NULL;
    int ret;
    debug("");
    
    signal(SIGPIPE, SIG_IGN);
    debug("");
    ctx = ubus_connect(ubus_socket);
    if (!ctx) {
        fprintf(stderr, "Failed to connect to ubus\n");
        return NULL;
    }

    ret = ubus_add_object(ctx, &spctrm_scn_object);
    if (ret) {
        fprintf(stderr, "Failed to add object: %s\n", ubus_strerror(ret));
        return;
    }

    debug("");
    ubus_add_uloop(ctx);
    debug("spctrm_scn_ubus_task");
}
void spctrm_scn_ubus_close()
{
    ubus_free(ctx);
}
