#include "spctrm_scn_wireless.h"

extern int8_t g_status;

void spctrm_scn_wireless_channel_scan(struct uloop_timeout *t) 
{
    struct spctrm_scn_ubus_set_request *hreq = container_of(t,struct spctrm_scn_ubus_set_request,timeout);
    static int i;

    if (i < hreq->scan_time) {
        spctrm_scn_wireless_get_channel_info(&hreq->device_info.bw20_channel_info[i],BAND_5G);
        debug("channel %d",hreq->device_info.bw20_channel_info[i].channel);
        debug("floornoise %d",hreq->device_info.bw20_channel_info[i].floornoise);
        debug("utilization %d",hreq->device_info.bw20_channel_info[i].utilization);
        hreq->timeout.cb = spctrm_scn_wireless_channel_scan; 
        i++;
    } else {
        hreq->timeout.cb = spctrm_scn_wireless_scan_task;
        i = 0;
    }
    uloop_timeout_set(&hreq->timeout,1000);
}

void spctrm_scn_wireless_scan_task(struct uloop_timeout *t) 
{
    struct spctrm_scn_ubus_set_request *hreq = container_of(t,struct spctrm_scn_ubus_set_request,timeout);
    static int i;
    uint8_t channel;
    static struct blob_buf buf;
    int fd;

    blob_buf_init(&buf, 0);
    blobmsg_add_string(&buf,"test","123");

    debug("");
    list_for_each_bitset(hreq->channel_bitmap,i) {
        debug("Bit %d is set\n", i);
        if (bitset_to_channel(i,&channel) == FAIL) {
            debug("error");
            goto fail;
        }
        debug("channel %d",channel);
        if (spctrm_scn_wireless_change_channel(channel) == FAIL) {
            debug("error");
            goto fail;
        }
        i++;
        hreq->timeout.cb = spctrm_scn_wireless_channel_scan; 
        uloop_timeout_set(&hreq->timeout,1000);
        return;
    }

    hreq->timeout.cb = spctrm_scn_wireless_channel_scan;
    uloop_timeout_set(&hreq->timeout,1000);

    g_status = SCAN_IDLE;
    i = 0;
    free(hreq);
    return;
fail:
    g_status = SCAN_ERROR;
    i = 0;
    free(hreq);
    return;
}
int spctrm_scn_wireless_change_channel(int channel) 
{
    char cmd[POPEN_BUFFER_MAX_SIZE];
    if (spctrm_scn_wireless_check_channel(channel) == FAIL) {
        debug("param error");
        return FAIL;
    }
    sprintf(cmd,"iwpriv ra0 set channel=%d",channel);
    if (spctrm_scn_common_cmd(cmd,NULL) == FAIL) {
        return FAIL;
    }
    
    return SUCCESS;
}
int spctrm_scn_wireless_get_channel_info(struct channel_info *info,int band) 
{
    char *rbuf;
    char *p;
    char cmd[POPEN_BUFFER_MAX_SIZE];

    if (info == NULL) {
        debug("FAIL");
        return FAIL;
    }

    if (band == BAND_5G) {
#ifdef BRIDGE_PLATFORM
        spctrm_scn_common_cmd("wlanconfig ra0 radio",&rbuf);
#elif defined AP_PLATFORM
        spctrm_scn_common_cmd("wlanconfig rax0 radio",&rbuf);
#else 
        return FAIL;
#endif
    } else if (band == BAND_2G) {
        return FAIL;
    } else {
        return FAIL;
    }
    
    debug("start");
    strtok(rbuf,"\n");

    strtok(NULL,":");
    p = strtok(NULL,"\n");
    if (p == NULL) {
        free(rbuf);
        debug("FAIL");
        return FAIL;
    }

    info->channel=atoi(p);
      
    strtok(NULL,":");
    p = strtok(NULL,"\n");
    if (p == NULL) {
        free(rbuf);
        debug("FAIL");
        return FAIL;
    }
    info->floornoise=atoi(p);
    debug("info->floornoise %d",info->floornoise);
    strtok(NULL,":");
    p = strtok(NULL,"\n");
    if (p == NULL) {
        debug("FAIL");
        free(rbuf);
        return FAIL;
    }
    info->utilization=atoi(p);
    debug("info->utilization %d",info->utilization);
    strtok(NULL,"\n");
    strtok(NULL,":");
    p = strtok(NULL,"\n");
    if (p == NULL) {
        free(rbuf);
        debug("FAIL");
        return FAIL;
    }
    info->bw = atoi(p);
    debug("info->bw %d",info->bw);
    
    strtok(NULL,":");
    p = strtok(NULL,"\n");
    if (p == NULL) {
        free(rbuf);
        return FAIL;
    }
    info->obss_util=atoi(p);
    debug("info->obss_util %d",info->obss_util);
    strtok(NULL,":");
    p = strtok(NULL,"\n");
    if (p == NULL) {
        free(rbuf);
        return FAIL;
    }
    info->tx_util=atoi(p);
    debug("info->tx_util %d",info->tx_util);
    strtok(NULL,":");

    p = strtok(NULL,"\n");
    if (p == NULL) {
        free(rbuf);
        return FAIL;
    }

    info->rx_util=atoi(p);
    debug("info->rx_util %d",info->rx_util);
    
    free(rbuf);

    return SUCCESS;
}

inline int spctrm_scn_wireless_band_check(uint8_t band) 
{
    if (band != BAND_5G && band != BAND_2G) {
        debug("bnad error");
        return FAIL;
    }
    return SUCCESS;
}

inline int spctrm_scn_wireless_check_channel(int channel)
{
    if (channel < 36 || channel > 181) {
        return FAIL;
    }

    if (channel >= 36 && channel <= 144) {
        if (channel % 4 != 0) {
            return FAIL;
        }
    }

    if (channel >= 149 && channel <= 181) {
        if ((channel - 1) % 4 != 0) {
            return FAIL;
        }
    }

    return SUCCESS;
}

int spctrm_scn_wireless_channel_score(struct device_list *list) 
{
    double N;

    if (list == NULL) {
        return FAIL;
    }

    
    return SUCCESS;
}


inline int channel_to_bitset(int channel,uint8_t *bitset)
{
    if (bitset == NULL) {
        return FAIL;
    }

    if (channel >= 36 && channel <= 144) {
        *bitset = channel/4 - 9;
    } else if (channel >= 149 && channel <= 181) {
        *bitset = (channel-1)/4 - 9;
    } else {
        return FAIL;
    }

    return SUCCESS;
    
    
}
inline int bitset_to_channel(int bit_set,uint8_t *channel)
{
    if (channel == NULL) {
        return FAIL;
    }

    if (bit_set >= 0 && bit_set <= 27) {
        *channel = (bit_set + 9 ) * 4;
    } else if (bit_set >= 28 && bit_set <= 45) {
        *channel = (bit_set + 9) * 4 + 1;
    } else {
        return FAIL;
    }

    return SUCCESS;
    
}
int spctrm_scn_wireless_get_wds_state(uint8_t *mode) 
{
    char *rbuf;
	json_object *rbuf_root;
    json_object *role_obj;

    if (spctrm_scn_common_cmd("dev_sta get -m wds_status", &rbuf) == FAIL) {
        debug("cmd fail");
        return FAIL;
    }
    rbuf_root = json_tokener_parse(rbuf);
    if (rbuf_root == NULL) {
        free(rbuf);
        return FAIL;
    }

    role_obj = json_object_object_get(rbuf_root,"role");
    if (role_obj == NULL) {
        free(rbuf);
        json_object_put(rbuf_root);
        return FAIL;
    }

    if (strcmp(json_object_get_string(role_obj),"cpe") == 0) {
        *mode = CPE_MODE;
    } else if (strcmp(json_object_get_string(role_obj),"ap") == 0) {
        *mode = AP_MODE;
    }

    free(rbuf);
    json_object_put(rbuf_root);
    debug("g_mode %d",*mode);
}

int spctrm_scn_wireless_country_channel(uint64_t *channel_bitmap,uint8_t *channel_num,uint8_t bw,uint8_t band)
{

#ifdef UNIFY_FRAMEWORK_ENABLE
    uf_cmd_msg_t *msg_obj;
#elif defined POPEN_CMD_ENABLE
    char cmd[POPEN_BUFFER_MAX_SIZE];
#endif     
    int ret;
    uint8_t temp[512];
    char *rbuf;
    const char *param;
    json_object *param_obj;
	int i;
    uint8_t bitset;
    struct json_object *ret_obj;
    struct json_object *elem;
	json_object *frequency_obj,*channel_obj;

    if (channel_bitmap == NULL || channel_num == NULL) {
        return FAIL;
    }

    if (spctrm_scn_wireless_band_check(band) == FAIL) {
        return FAIL;
    }

	param_obj = json_object_new_object();
    if (param_obj == NULL) {
        debug("");
        return FAIL;
    }

    switch (bw) {
    case BW_20:
        json_object_object_add(param_obj, "band", json_object_new_string("BW_20"));
        break;
    case BW_40:
        json_object_object_add(param_obj, "band", json_object_new_string("BW_40"));
        break;
    case BW_80:
        json_object_object_add(param_obj, "band", json_object_new_string("BW_80"));
        break;
    case BW_160:
        json_object_object_add(param_obj, "band", json_object_new_string("BW_160"));
        break;
    default:
        json_object_put(param_obj);
        return FAIL;
    }
 
    rbuf = NULL;
    *channel_bitmap = 0;
    json_object_object_add(param_obj, "qry_type", json_object_new_string("channellist"));
    json_object_object_add(param_obj, "range", json_object_new_string("5G"));

    param = json_object_to_json_string(param_obj);
    if (param == NULL) {
        debug("");
        json_object_put(param_obj);
        return FAIL;
    }
	debug("%s\n",param);

#ifdef UNIFY_FRAMEWORK_ENABLE
    msg_obj = (uf_cmd_msg_t*)malloc(sizeof(uf_cmd_msg_t));
    if (msg_obj == NULL) {
        json_object_put(param_obj);
        return FAIL;
    }
    memset(msg_obj, 0, sizeof(uf_cmd_msg_t));

    msg_obj->param = param;
    msg_obj->ctype = UF_DEV_STA_CALL;    /* 调用类型 ac/dev/.. */
    msg_obj->cmd = "get";
    msg_obj->module = "country_channel";               /* 必填参数，其它可选参数根据需要使用 */
    msg_obj->caller = "group_change";       /* 自定义字符串，标记调用者 */
    ret = uf_client_call(msg_obj, &rbuf, NULL);
    if (ret == FAIL) {
        json_object_put(param_obj);
        return FAIL;      
    }
    debug("%s\n",rbuf);

#elif defined POPEN_CMD_ENABLE
	debug("%s\n",param);
    sprintf(cmd,"dev_sta get -m country_channel '%s'",param);
    debug("%s\r\n",cmd);
    spctrm_scn_common_cmd(cmd,&rbuf);    
#endif

	ret_obj=json_tokener_parse(rbuf);
    if (ret_obj == NULL) {
        debug("");
        json_object_put(param_obj);
        free(rbuf);
        return FAIL;
    }

    if (band == BAND_5G) {
        *channel_num = json_object_array_length(ret_obj);
        debug("channel_num %d",*channel_num);
        for (i = 0; i < *channel_num; i++) {
            elem = json_object_array_get_idx(ret_obj, i);
            channel_obj = json_object_object_get(elem, "channel");
            if (channel_obj == NULL) {
                debug("");
                json_object_put(param_obj);
                json_object_put(ret_obj);
                free(rbuf);
                return FAIL;
            }
            memset(temp,0,sizeof(temp));
            strcpy(temp,json_object_get_string(channel_obj));
            debug("%s\r\n",temp);

            if (channel_to_bitset(atoi(temp),&bitset) == FAIL) {
                debug("");
                json_object_put(param_obj);
                json_object_put(ret_obj);
                free(rbuf);
                return FAIL; 
            }

            *channel_bitmap |= ((uint64_t)1) << bitset;  /*36 ~ 144    149 153 157 161 165 169 173 177 181*/
        }
    }
    debug("channel_bitmap = %lld",*channel_bitmap);
    i = 0;
    list_for_each_bitset(*channel_bitmap,i) {
        debug("Bit %d is set\n", i);
    }

    json_object_put(param_obj);
    json_object_put(ret_obj);
    /* 资源需要调用者释放 */
    if (rbuf) {
      free(rbuf);
    }
#ifdef UNIFY_FRAMEWORK_ENABLE
    free(msg_obj);
#endif
	return SUCCESS;
}