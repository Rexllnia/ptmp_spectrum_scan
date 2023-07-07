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
#include "spctrm_scn_config.h"
#include "spctrm_scn_dev.h"
#include <stdbool.h>
#include <stdio.h>

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
struct spctrm_scn_ubus_set_request
{
    struct ubus_request_data req;
    struct uloop_timeout timeout;
    int fd;
    int idx;
    char data[];
};

struct ubus_connect_ctx *ctx;
static const struct blobmsg_policy scan_policy[] = {
    [BAND] = {.name = "band", .type = BLOBMSG_TYPE_INT32},
    [CHANNEL_LIST] = {.name = "channel_list", .type = BLOBMSG_TYPE_ARRAY},
    [SCAN_TIME] = {.name = "scan_time", .type = BLOBMSG_TYPE_INT32},
};
static const struct ubus_method spctrm_scn_methods[] = {
    UBUS_METHOD_NOARG("get", spctrm_scn_ubus_get),
    UBUS_METHOD("set", spctrm_scn_ubus_set, scan_policy),
};
static struct ubus_object_type spctrm_scn_object_type =
    UBUS_OBJECT_TYPE("spctrm_scn", spctrm_scn_methods);

static struct ubus_object spctrm_scn_object = {
    .name = "spctrm_scn",
    .type = &spctrm_scn_object_type,
    .methods = spctrm_scn_methods,
    .n_methods = ARRAY_SIZE(spctrm_scn_methods),
};

static int spctrm_scn_ubus_set(struct ubus_context *ctx, struct ubus_object *obj,
		      struct ubus_request_data *req, const char *method,
		      struct blob_attr *msg)
{
    
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
