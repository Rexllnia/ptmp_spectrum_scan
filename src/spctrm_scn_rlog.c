#include "spctrm_scn_rlog.h"

static struct ubus_context *ctx;
static struct blob_buf b;
static int module_enable_result;
enum
{
    RESULT,
    __RESULT_MAX
};
static const struct blobmsg_policy result_policy[] = {
    [RESULT] = {.name = "result", .type = BLOBMSG_TYPE_STRING},
};
 

static void scanreq_prog_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
    struct blob_attr *tb[__RESULT_MAX];
 
    blobmsg_parse(result_policy, ARRAY_SIZE(result_policy), tb, blob_data(msg), blob_len(msg));
    module_enable_result = atoi(blobmsg_get_string(tb[RESULT]));    
}
int spctrm_scn_rlog_module_set() {
    json_object *root;
    FILE *fp;
    char *rbuf;
    
    fp = fopen("/etc/rlog/module.json","r+");
    if (fp == NULL) {
        return FAIL;
    }
    root = json_object_from_fp(fp);
    rbuf = json_object_to_json_string(root);
    debug("%s",rbuf);

    free(rbuf);
    json_object_put(root);
    fclose(fp);
}
int spctrm_scn_rlog_module_enable() {
    const char *ubus_socket = NULL;
    unsigned int id;
    int ret;
    int timeout = 30;
    ctx = ubus_connect(ubus_socket);
    if (!ctx)
    {
        fprintf(stderr, "Failed to connect to ubus\n");
        return FAIL;
    }
 
    blob_buf_init(&b, 0);
 
    blobmsg_add_string(&b,"module", "spectrum_scan");
 
    ret = ubus_lookup_id(ctx, "rlog", &id);
    if (ret != UBUS_STATUS_OK)
    {
        printf("lookup scan_prog failed\n");
        return FAIL;
    } else {
        printf("lookup scan_prog successs\n");
    }
    ubus_invoke(ctx, id, "module_enable", b.head, scanreq_prog_cb, NULL, timeout * 1000);
    ubus_free(ctx);

    ret = module_enable_result;
    return ret;
}