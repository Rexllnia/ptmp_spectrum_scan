/* spctrm_scn_ubus.h*/
#ifndef _SPCTRM_SCN_UBUS_H_
#define _SPCTRM_SCN_UBUS_H_

#include <unistd.h>
#include <signal.h>
#include <semaphore.h>
#include <json-c/json.h>
#include <libubox/blobmsg_json.h>
#include "libubus.h"
#include "spctrm_scn_wireless.h"
#include "spctrm_scn_config.h"
#include "spctrm_scn_dev.h"
#include "spctrm_scn_tipc.h"



#define MAX_CHANNEL_NUM 200 

enum {
	BAND,
    CHANNEL_BITMAP,
    SCAN_TIME,
	__SCAN_MAX
};

void *spctrm_scn_ubus_thread(void *arg);

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
#endif
