
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/wait.h>

#define UBUS_RLOG_STATUS    "rlog"
#define WIO_V2_RLOG_REG_CHECK_INTERVAL   5 * 1000

static struct ubus_subscriber g_wio_v2_rlog_ststus;
static uint32_t g_wio_v2_ubus_rlog_ststus_id;
static int g_wio_v2_rlog_status;
extern struct ubus_context *apcway_ubus_get_ctx();

int wio_v2_get_rlog_status(void)
{
    return __sync_sub_and_fetch(&g_wio_v2_rlog_status, 0);
}

void  wio_v2_rlog_statusdump(void)
{
    char *rlog_mode[] = {
        "DISABLE",
        "ENABLE",
    };

    if (__sync_sub_and_fetch(&g_wio_v2_rlog_status, 0) < WIO_V2_RLOG_STATUS_MAX) {
        WIO_V2_COMMON_LOGD(WIO_V2_MACC, "RLOG STATUS:    %s\n", rlog_mode[__sync_sub_and_fetch(&g_wio_v2_rlog_status, 0)]);
    }
}

static int wio_v2_set_rlog_status(int status)
{
    if (status >= WIO_V2_RLOG_STATUS_MAX) {
        WIO_V2_COMMON_LOGD(WIO_V2_MACC, "rlog status new_value is out of max %d", status);
        return WIO_V2_INVALID_PARAM;
    } else {
        __sync_lock_test_and_set(&g_wio_v2_rlog_status, status);
    }

    return WIO_V2_SUC;
}

int wio_v2_rlog_status_init(void)
{
    char *result = NULL;
    struct json_object *root;
    const char *tmp;

    if ((roam_usr_common_call_unifyframe_mod(&result, ROAM_USR_COMMON_UNI_CALLER_WIOV2, ROAM_USR_COMMON_UNI_TYPE_DEV_STA, ROAM_USR_COMMON_UNI_METHOD_GET,
        ROAM_USR_COMMON_UNI_MODULE_CALL_RLOG_ENABLE, "{\"module\":\"wioV2\"}", NULL) == ROAM_USR_COMMON_SUC) && result) {
        root = json_tokener_parse(result);
        if (root == NULL) {
            WIO_V2_COMMON_LOGD(WIO_V2_MACC, "init rlog status root is NULL ...\n");
            free(result);
            return WIO_V2_NOT_FOUND;
        }

        tmp = roam_usr_common_json_parse_str(root, "result");
        if (tmp == NULL) {
            WIO_V2_COMMON_LOGE(WIO_V2_MACC, "init rlog status new_value is NULL \n");
            free(result);
            json_object_put(root);
            return WIO_V2_NOT_FOUND;
        }

        wio_v2_set_rlog_status(atoi(tmp));
        json_object_put(root);
        free(result);

        return WIO_V2_SUC;
    }

    if (result) {
        free(result);
    }

    return WIO_V2_ERR;
}

static int wio_v2_rlog_status_updata(struct ubus_context *ctx, struct ubus_object *obj, struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
    char *buf;
    struct json_object *root;
    struct json_object *node, *node_arr;
    const char *tmp;
    int ret = WIO_V2_SUC;
    int json_ret;
    int total_num;
    int i;

    buf = blobmsg_format_json(msg, true);
    if (!buf) {
        WIO_V2_COMMON_LOGE(WIO_V2_MACC, "rlog status failed");
        return WIO_V2_NOT_FOUND;
    }

    root = json_tokener_parse(buf);
    if (root == NULL) {
        WIO_V2_COMMON_LOGE(WIO_V2_MACC, "rlog status root is NULL ...\n");
        ret = WIO_V2_NOT_FOUND;
        goto exit;
    }

    tmp = roam_usr_common_json_parse_str(root, "total");
    if (tmp == NULL) {
        WIO_V2_COMMON_LOGE(WIO_V2_MACC, "rlog status new_value is NULL \n");
        ret = WIO_V2_NOT_FOUND;
        goto exit;
    }

    total_num = atoi(tmp);
    if (total_num <= 0) {
        WIO_V2_COMMON_LOGE(WIO_V2_MACC, "rlog status total num = 0\n");
        goto exit;
    }

    json_ret = json_object_object_get_ex(root, "config", &node);
    if (!json_ret) {
        WIO_V2_COMMON_LOGE(WIO_V2_MACC, "Not found config object failed!\n");
        goto exit;
    }

    if (json_object_array_length(node) != total_num) {
        WIO_V2_COMMON_LOGE(WIO_V2_MACC, "json total (%d) != array num(%d)\n", total_num, json_object_array_length(node));
        total_num = json_object_array_length(node);
    }

    for (i = 0; i < total_num; i++) {
        node_arr = json_object_array_get_idx(node, i);
        if (node_arr == NULL) {
            WIO_V2_COMMON_LOGE(WIO_V2_MACC, "rlog status get array object failed!\n");
            goto exit;
        }
        tmp = roam_usr_common_json_parse_str(node_arr, "name");
        if (tmp == NULL) {
            continue;
        }

        if (strcmp(tmp, "wioV2") == 0) {
            tmp = roam_usr_common_json_parse_str(node_arr, "option");
            if (tmp == NULL) {
                WIO_V2_COMMON_LOGE(WIO_V2_MACC, "rlog option is NULL \n");
                ret = WIO_V2_NOT_FOUND;
                goto exit;
            }

            if (strcmp(tmp, "enable") == 0) {
                tmp = roam_usr_common_json_parse_str(node_arr, "new_value");
                if (tmp == NULL) {
                    WIO_V2_COMMON_LOGE(WIO_V2_MACC, "rlog status new_value is NULL \n");
                    ret = WIO_V2_NOT_FOUND;
                    goto exit;
                }
                wio_v2_set_rlog_status(atoi(tmp));
            }
        }
    }

exit:
    if (root) {
        json_object_put(root);
    }

    if (buf) {
        free(buf);
    }

    return ret;
}

static void wio_v2_rlog_ubus_retry_reg_timer()
{
    struct ubus_context *ctx = apcway_ubus_get_ctx();
    static struct uloop_timeout retry = {
        .cb = wio_v2_rlog_ubus_retry_reg_timer,
    };

    if (wio_v2_rlog_status_ubus_init(ctx) != WIO_V2_SUC) {
        uloop_timeout_set(&retry, WIO_V2_RLOG_REG_CHECK_INTERVAL);
    }

    return;
}

static void wio_v2_rlog_status_remove(struct ubus_context *ctx, struct ubus_subscriber *obj, uint32_t id)
{
    WIO_V2_COMMON_LOGE(WIO_V2_MACC, "ubus subscribe UBUS_RLOG_STATUS is remove!\n");
    ubus_unsubscribe(ctx, &g_wio_v2_rlog_ststus, g_wio_v2_ubus_rlog_ststus_id);
    ubus_remove_object(ctx, &g_wio_v2_rlog_ststus.obj);
    wio_v2_rlog_ubus_retry_reg_timer();
}

int wio_v2_rlog_status_ubus_init(struct ubus_context *ctx)
{
    int ret;

    g_wio_v2_rlog_ststus.cb = wio_v2_rlog_status_updata;
    g_wio_v2_rlog_ststus.remove_cb = wio_v2_rlog_status_remove;

    ret = ubus_register_subscriber(ctx, &g_wio_v2_rlog_ststus);
    if (ret) {
        WIO_V2_COMMON_LOGE(WIO_V2_MACC, "ubus_register_subscriber UBUS_RLOG_STATUS failed!\n");
        return WIO_V2_ERR;
    }

    ret = ubus_lookup_id(ctx, UBUS_RLOG_STATUS, &g_wio_v2_ubus_rlog_ststus_id);
    if (ret) {
        WIO_V2_COMMON_LOGE(WIO_V2_MACC, "ubus_lookup_id UBUS_RLOG_STATUS failed!\n");
        ubus_remove_object(ctx, &g_wio_v2_rlog_ststus.obj);
        return WIO_V2_ERR;
    }

    ret = ubus_subscribe(ctx, &g_wio_v2_rlog_ststus, g_wio_v2_ubus_rlog_ststus_id);
    if (ret) {
        WIO_V2_COMMON_LOGE(WIO_V2_MACC, "ubus_subscribe UBUS_RLOG_STATUS failed!\n");
        ubus_remove_object(ctx, &g_wio_v2_rlog_ststus.obj);
        return WIO_V2_ERR;
    }

    WIO_V2_COMMON_LOGE(WIO_V2_MACC, "ubus_subscribe UBUS_RLOG_STATUS suc!\n");

    return WIO_V2_SUC;
}

void wio_v2_rlog_ubus_exit(struct ubus_context *ctx)
{
    ubus_unsubscribe(ctx, &g_wio_v2_rlog_ststus, g_wio_v2_ubus_rlog_ststus_id);
}



