#include "spctrm_scn_wireless.h"

static int timeout_func();
static double calculate_N(struct channel_info *info);
static inline channel_to_bitmap (int channel);
static inline bitmap_to_channel (int bit_set);
static void channel_scan(struct channel_info *input,int scan_time);
extern char g_wds_bss[20];
extern unsigned char g_mode;
extern struct device_list g_finished_device_list;
extern struct device_list g_device_list;
extern struct channel_info g_channel_info_5g[MAX_BAND_5G_CHANNEL_NUM];
extern struct channel_info realtime_channel_info_5g[MAX_BAND_5G_CHANNEL_NUM];
int g_scan_schedule;
extern struct user_input g_input;
volatile int g_status,g_scan_time;
extern volatile uint64_t g_scan_timestamp;
extern uint64_t g_bitmap_2G,g_bitmap_5G;
extern pthread_mutex_t g_mutex,g_finished_device_list_mutex;
extern pthread_mutex_t g_scan_schedule_mutex;
extern sem_t g_semaphore;
time_t g_current_time;
extern int g_bw40_channel_num;
extern int g_bw80_channel_num;
int spctrm_scn_wireless_get_wds_bss(char *wds_bss)
{
    json_object *root,*wireless_obj,*wds_bss_obj,*radiolist_obj;
    json_object *radiolist_elem_obj,*band_support_obj;
    int i;

    if (wds_bss == NULL) {
        return FAIL;
    }

    root = json_object_from_file("/tmp/rg_device/rg_device.json");
    if (root == NULL) {
        SPCTRM_SCN_DBG_FILE("\nFAIL\n");
        json_object_put(root);
        return FAIL;
    }
    wireless_obj = json_object_object_get(root,"wireless");
    if (wireless_obj == NULL) {
        SPCTRM_SCN_DBG_FILE("\nFAIL\n");
        json_object_put(root);
        return FAIL;
    }

    radiolist_obj = json_object_object_get(wireless_obj,"radiolist");

    for (i = 0;i < json_object_array_length(radiolist_obj);i++) {
        radiolist_elem_obj = json_object_array_get_idx(radiolist_obj,i);
        band_support_obj = json_object_object_get(radiolist_elem_obj,"band_support");
        if (strcmp(json_object_get_string(band_support_obj),"5G") == 0) {
            wds_bss_obj = json_object_object_get(radiolist_elem_obj,"wds_bss");
            if (wds_bss_obj == NULL) {
                SPCTRM_SCN_DBG_FILE("\nFAIL\n");
                json_object_put(root);
                return FAIL;
            }
            break;
        }
    }



    strcpy(wds_bss,json_object_get_string(wds_bss_obj));

    json_object_put(root);
    return SUCCESS;


}
void spctrm_scn_wireless_set_status() {
    json_object *root;
    char temp[128];

    root = json_object_from_file("/etc/spectrum_scan_cache");
    if (root == NULL) {
        return;
    }

    if (g_status == SCAN_BUSY) {
        json_object_object_add(root,"status",json_object_new_string("busy"));
    } else if(g_status == SCAN_IDLE) {
        json_object_object_add(root,"status",json_object_new_string("idle"));
    } else if(g_status == SCAN_ERR) {
        json_object_object_add(root,"status",json_object_new_string("error"));
    }

    sprintf(temp,"%d",g_status);
    json_object_object_add(root,"status_code",json_object_new_string(temp));

    json_object_to_file("/etc/spectrum_scan_cache",root);
    json_object_put(root);
}
int spctrm_scn_wireless_set_current_channel_info(struct channel_info *current_channel_info)
{
    json_object *root;
    char temp[128];

    if (access("/etc/spectrum_scan/current_channel_info",F_OK) == FAIL) {
        SPCTRM_SCN_DBG_FILE("\nnot exit");
        creat("/etc/spectrum_scan/current_channel_info",0777);
    }

    root = json_object_new_object();
    if (root == NULL) {
        return FAIL;
    }

    sprintf(temp,"%d",current_channel_info->channel);
    json_object_object_add(root,"current_channel",json_object_new_string(temp));
    sprintf(temp,"%d",current_channel_info->bw);
    json_object_object_add(root,"current_bw",json_object_new_string(temp));
    json_object_to_file("/etc/spectrum_scan/current_channel_info",root);
    json_object_put(root);

    return SUCCESS;
}
int spctrm_scn_wireless_get_current_channel_info (struct channel_info *current_channel_info)
{
    json_object *root;
    json_object *current_channel_obj,*current_bw_obj;
    const char *current_channel_str,*current_bw_str;

    root = json_object_from_file("/etc/spectrum_scan/current_channel_info");
    if (root == NULL) {
        return FAIL;
    }
    SPCTRM_SCN_DBG_FILE("\n%s",json_object_to_json_string(root));
    current_channel_obj = json_object_object_get(root,"current_channel");
    if (current_channel_obj == NULL) {
        json_object_put(root);
        return FAIL;
    }

    current_channel_str = json_object_get_string(current_channel_obj);
    if (current_channel_str == NULL) {
        json_object_put(root);
        return FAIL;
    }
    current_channel_info->channel = atoi(current_channel_str);

    current_bw_obj = json_object_object_get(root,"current_bw");
    if (current_bw_obj == NULL) {
        json_object_put(root);
        return FAIL;
    }

    current_bw_str = json_object_get_string(current_bw_obj);
    if (current_bw_str == NULL) {
        json_object_put(root);
        return FAIL;
    }

    current_channel_info->bw = atoi(current_bw_str);

    return SUCCESS;
}
int spctrm_scn_wireless_restore_device_info(char *path,struct device_list *device_list)
{
    json_object *root,*scan_list_obj;
    struct json_object* scan_list_elem,*status_obj,*sn_obj,*role_obj,*band_5g_obj;
    json_object *bw20_obj;
    json_object *score_list_obj,*score_list_elem_obj,*channel_obj,*score_obj;
    int i;
    int j,k;
    struct device_info *p;
    root = json_object_from_file(path);
    if (root == NULL) {

        return FAIL;
    }
    SPCTRM_SCN_DBG_FILE("%s\n",json_object_to_json_string(root));
    scan_list_obj = json_object_object_get(root,"scan_list");
    device_list->list_len = json_object_array_length(scan_list_obj);
    SPCTRM_SCN_DBG_FILE("%d",device_list->list_len);
    list_for_each_device(p,i,device_list) {

        scan_list_elem = json_object_array_get_idx(scan_list_obj,i);
        status_obj = json_object_object_get(scan_list_elem,"status");
        if (status_obj != NULL) {
            p->status = atoi(json_object_get_string(status_obj));
            SPCTRM_SCN_DBG_FILE("p->status %d\n",p->status);
        }

        role_obj = json_object_object_get(scan_list_elem,"role");
        if (role_obj != NULL) {
            strcpy(p->role,json_object_get_string(role_obj));
            SPCTRM_SCN_DBG_FILE("p->role %s\n",p->role);
        }

        sn_obj = json_object_object_get(scan_list_elem,"SN");
        if (sn_obj != NULL) {
            strcpy(p->series_no,json_object_get_string(sn_obj));
            SPCTRM_SCN_DBG_FILE("p->series_no %s \n",p->series_no);
        }

        band_5g_obj = json_object_object_get(scan_list_elem,"5G");
        bw20_obj = json_object_object_get(band_5g_obj,"bw_20");
        score_list_obj = json_object_object_get(bw20_obj,"score_list");

        for (k = 0;k < json_object_array_length(score_list_obj);k++) {
            score_list_elem_obj = json_object_array_get_idx(score_list_obj,k);
            channel_obj = json_object_object_get(score_list_elem_obj,"channel");


            if (channel_obj != NULL) {
                p->channel_info[k].channel = atoi(json_object_get_string(channel_obj));
                SPCTRM_SCN_DBG_FILE("channel %d\n",p->channel_info[k].channel);
            }

            score_obj = json_object_object_get(score_list_elem_obj,"score");
            if (score_obj != NULL) {
                sscanf(json_object_get_string(score_obj),"%lf",&(p->channel_info[k].score));
                SPCTRM_SCN_DBG_FILE("score %f \n ",p->channel_info[k].score);
            }
        }
    }
    p = spctrm_scn_dev_find_ap2(&g_finished_device_list);
    memcpy(g_channel_info_5g,p->channel_info,sizeof(g_channel_info_5g));

    SPCTRM_SCN_DBG_FILE("%d\n",p->channel_info[0].channel);
    SPCTRM_SCN_DBG_FILE("%d\n",p->channel_info[1].channel);
    SPCTRM_SCN_DBG_FILE("%d\n",p->channel_info[2].channel);
    SPCTRM_SCN_DBG_FILE("%d\n",p->channel_info[3].channel);

    SPCTRM_SCN_DBG_FILE("%d\n",g_channel_info_5g[0].channel);
    SPCTRM_SCN_DBG_FILE("%d\n",g_channel_info_5g[1].channel);
    SPCTRM_SCN_DBG_FILE("%d\n",g_channel_info_5g[2].channel);
    SPCTRM_SCN_DBG_FILE("%d\n",g_channel_info_5g[3].channel);

    json_object_put(root);
}
int spctrm_scn_wireless_check_status(char *path)
{
    json_object *root;
    json_object *status_obj,*current_channel_obj,*current_bw_obj;
    char *rbuf;
    const char *status_str;
    int status;
    struct channel_info current_channel_info;

    SPCTRM_SCN_DBG_FILE("\nfile exit");
    root = json_object_from_file(path);
    if (root == NULL) {
        return FAIL;
    }

    status_obj = json_object_object_get(root,"status_code");
    if (status_obj == NULL) {
        json_object_put(root);
        return FAIL;
    }
    status_str = json_object_get_string(status_obj);
    if (status_str == NULL) {
        json_object_put(root);
        return FAIL;
    }
    SPCTRM_SCN_DBG_FILE("\n%s",status_str);
    status = atoi(status_str);
    if (status == SCAN_IDLE) {
        SPCTRM_SCN_DBG_FILE("\nSCAN_IDLE");
    } else if (status == SCAN_BUSY) {
        SPCTRM_SCN_DBG_FILE("\nSCAN_BUSY");
        g_status = SCAN_ERR;
        spctrm_scn_wireless_get_current_channel_info(&current_channel_info);
        spctrm_scn_wireless_change_channel(current_channel_info.channel);
        spctrm_scn_wireless_change_bw(current_channel_info.bw);
        spctrm_scn_wireless_set_status();
    } else if (status == SCAN_ERR) {
        SPCTRM_SCN_DBG_FILE("\nSCAN_ERR");
        g_status = status;
    }
    json_object_put(root);
    return SUCCESS;
}

void spctrm_scn_wireless_change_bw(int bw)
{
    switch (bw)
    {
    case BW_20:
        spctrm_scn_common_cmd("iwpriv ra0 set HtBw=0",NULL);
        break;
    case BW_40:
        spctrm_scn_common_cmd("iwpriv ra0 set HtBw=1",NULL);
        break;
    case BW_80:
        spctrm_scn_common_cmd("iwpriv ra0 set VhtBw=1",NULL);
        break;
    default:
        break;
    }
}
static void print_bits(uint64_t num) {
    int i;

    for (i = 0; i < sizeof(uint64_t) * 8; i++) {
        if ((num & (((uint64_t)1)<< i)) != 0) {
            SPCTRM_SCN_DBG_FILE("\nBit %d is set\n", i);
        }
    }
}

#ifdef AP_PLATFORM

#elif defined BRIDGE_PLATFORM
int spctrm_scn_wireless_get_country_channel_bwlist(uint8_t *bw_bitmap)
{
    int array_len,i;
    char cmd[MAX_POPEN_BUFFER_SIZE];
    char *rbuf;
    json_object *root;
    json_object *bandwidth_5G_obj,*elem;
    char *bw_str;

    if (bw_bitmap == NULL) {
        return FAIL;
    }
    SPCTRM_SCN_DBG_FILE("\n");
    if (spctrm_scn_common_cmd("dev_sta get -m country_channel '{\"qry_type\": \"bandwidth_list\"}'",&rbuf) == FAIL) {
        if (rbuf != NULL) {
            free (rbuf);
        }
        return FAIL;
    }

    SPCTRM_SCN_DBG_FILE("\n%s",rbuf);
    root = json_tokener_parse(rbuf);
    if (root == NULL) {
        if (rbuf != NULL) {
            free (rbuf);
        }
        return FAIL;
    }
    SPCTRM_SCN_DBG_FILE("\n");
    bandwidth_5G_obj = json_object_object_get(root,"bandwidth_5G");
    if (bandwidth_5G_obj == NULL) {
        if (rbuf != NULL) {
            free (rbuf);
        }
        json_object_put(root);
        return FAIL;
    }

    array_len = 0;
    array_len = json_object_array_length(bandwidth_5G_obj);
    SPCTRM_SCN_DBG_FILE("\n");
    *bw_bitmap = 0;
    for (i = 0;i < array_len;i++) {
        elem = json_object_array_get_idx(bandwidth_5G_obj, i);
        SPCTRM_SCN_DBG_FILE("\n");
        if (strcmp(json_object_get_string(elem),"20") == 0) {
            *bw_bitmap |= 1;
        } else if (strcmp(json_object_get_string(elem),"40") == 0) {
            *bw_bitmap |= 1 << 1;
        } else if (strcmp(json_object_get_string(elem),"80") == 0) {
            *bw_bitmap |= 1 << 2;
        }
    }

    SPCTRM_SCN_DBG_FILE("\nbw_bitmap %d",*bw_bitmap);





    if (rbuf != NULL) {
        free (rbuf);
    }
    json_object_put(root);
    return SUCCESS;
}
int spctrm_scn_wireless_country_channel(int bw,uint64_t *bitmap_2G,uint64_t *bitmap_5G,int band)
{

#ifdef UNIFY_FRAMEWORK_ENABLE
    uf_cmd_msg_t *msg_obj;
#elif defined POPEN_CMD_ENABLE
    char cmd[MAX_POPEN_BUFFER_SIZE];
#endif
    int ret;
    int channel_num;
    char *rbuf;
    const char *param_input;
    json_object *input_param_root,*output_param_root;
    json_object *qry_type_obj,*band_obj;
    int i,p;
    struct json_object *elem;
    json_object *frequency_obj,*channel_obj;
    char channel[8],frequency[8]; /* 信道字符串 */


    if (band != PLATFORM_5G && band != PLATFORM_2G) {
        SPCTRM_SCN_DBG_FILE("\n");
        return FAIL;
    }

    input_param_root = json_object_new_object();
    if (input_param_root == NULL) {
        SPCTRM_SCN_DBG_FILE("\n");
        return FAIL;
    }

    if (bw == BW_20) {
        json_object_object_add(input_param_root, "band", json_object_new_string("BW_20"));
    } else if (bw == BW_40) {
        json_object_object_add(input_param_root, "band", json_object_new_string("BW_40"));
    } else if (bw == BW_80) {
        json_object_object_add(input_param_root, "band", json_object_new_string("BW_80"));
    } else if (bw == BW_160) {
        json_object_object_add(input_param_root, "band", json_object_new_string("BW_160"));
    } else {
        SPCTRM_SCN_DBG_FILE("\n");
        json_object_put(input_param_root);
        return FAIL;
    }

    if (bitmap_2G == NULL || bitmap_5G == NULL) {
        SPCTRM_SCN_DBG_FILE("\n");
        json_object_put(input_param_root);
        return FAIL;
    }

    *bitmap_2G = 0;
    *bitmap_5G = 0;


    rbuf = NULL;

    json_object_object_add(input_param_root, "qry_type", json_object_new_string("channellist"));
    json_object_object_add(input_param_root, "range", json_object_new_string("5G"));

    param_input = json_object_to_json_string(input_param_root);
    if (param_input == NULL) {
        SPCTRM_SCN_DBG_FILE("\n");
        json_object_put(input_param_root);
        return FAIL;
    }
    SPCTRM_SCN_DBG_FILE("\n%s\n",param_input);

#ifdef UNIFY_FRAMEWORK_ENABLE
    msg_obj = (uf_cmd_msg_t*)malloc(sizeof(uf_cmd_msg_t));
    if (msg_obj == NULL) {
        json_object_put(input_param_root);
        return FAIL;
    }
    memset(msg_obj, 0, sizeof(uf_cmd_msg_t));

    msg_obj->param = param_input;
    msg_obj->ctype = UF_DEV_STA_CALL;    /* 调用类型 ac/dev/.. */
    msg_obj->cmd = "get";
    msg_obj->module = "country_channel";               /* 必填参数，其它可选参数根据需要使用 */
    msg_obj->caller = "group_change";       /* 自定义字符串，标记调用者 */
    ret = uf_client_call(msg_obj, &rbuf, NULL);
    if (ret == FAIL) {
        json_object_put(input_param_root);
        return FAIL;
    }
    SPCTRM_SCN_DBG_FILE("\n%s\n",rbuf);

#elif defined POPEN_CMD_ENABLE
    SPCTRM_SCN_DBG_FILE("\n%s\n",param_input);
    sprintf(cmd,"dev_sta get -m country_channel '%s'",param_input);
    SPCTRM_SCN_DBG_FILE("\n%s\r\n",cmd);
    spctrm_scn_common_cmd(cmd,&rbuf);
#endif

    output_param_root=json_tokener_parse(rbuf);
    if (output_param_root == NULL) {
        ret = FAIL;
        SPCTRM_SCN_DBG_FILE("\n");
        goto output_param_root_error;
    }

    if (band == PLATFORM_5G || band == PLATFORM_BOTH) {
        channel_num = json_object_array_length(output_param_root);
        SPCTRM_SCN_DBG_FILE("\nchannel_num %d",channel_num);
        for (i = 0; i < channel_num; i++) {
            elem = json_object_array_get_idx(output_param_root, i);
            frequency_obj = json_object_object_get(elem, "frequency");
            if (frequency_obj == NULL) {
                ret = FAIL;
                SPCTRM_SCN_DBG_FILE("\n");
                goto clear;
            }
            channel_obj = json_object_object_get(elem, "channel");
            if (channel_obj == NULL) {
                ret = FAIL;
                SPCTRM_SCN_DBG_FILE("\n");
                goto clear;
            }
            strcpy(channel,json_object_get_string(channel_obj));
            SPCTRM_SCN_DBG_FILE("\n%s\r\n",channel);
            *bitmap_5G |= ((uint64_t)1) << channel_to_bitmap(atoi(channel));  /*36 ~ 144    149 153 157 161 165 169 173 177 181*/
        }
    }
    if (band == PLATFORM_2G || band == PLATFORM_BOTH) {
        channel_num = json_object_array_length(output_param_root);
        for (i = 0; i < channel_num; i++) {
            struct json_object *elem = json_object_array_get_idx(output_param_root, i);
            frequency_obj = json_object_object_get(elem, "frequency");
            if (frequency_obj == NULL) {
                ret = FAIL;
                SPCTRM_SCN_DBG_FILE("\n");
                goto clear;
            }
            channel_obj = json_object_object_get(elem, "channel");
            if (channel_obj == NULL) {
                ret = FAIL;
                SPCTRM_SCN_DBG_FILE("\n");
                goto clear;
            }
            strcpy(channel,json_object_get_string(channel_obj));
            SPCTRM_SCN_DBG_FILE("\n%s\r\n",channel);
            *bitmap_2G |= ((uint64_t)1)<< atoi(channel);
        }
    }
    SPCTRM_SCN_DBG_FILE("\nbitmap_5G %llu\n",*bitmap_5G);
    SPCTRM_SCN_DBG_FILE("\nbitmap_2G %u\n",*bitmap_2G);
    print_bits(*bitmap_5G);
    ret = channel_num;

clear:
    json_object_put(output_param_root);
output_param_root_error:
    json_object_put(input_param_root);
    /* 资源需要调用者释放 */
    if (rbuf) {
      free(rbuf);
    }

#ifdef UNIFY_FRAMEWORK_ENABLE
    free(msg_obj);
#endif
    return ret;
}
#endif

static inline int channel_to_bitmap (int channel)
{
    if (channel >= 36 && channel <= 144) {
        return channel/4 - 9;
    }
    if (channel >= 149 && channel <= 181) {
        return (channel-1)/4 - 9;
    }
    return FAIL;

}

static inline int bitmap_to_channel (int bit_set)
{
    if (bit_set >= 0 && bit_set <= 27) {
        return (bit_set + 9 ) * 4;
    }
    if (bit_set >= 28 && bit_set <= 45) {
        return (bit_set + 9) * 4 + 1;
    }
    return FAIL;
}

void *spctrm_scn_wireless_ap_scan_thread()
{
    int i,j;
    char rlog_str[64],temp[256];
    struct channel_info current_channel_info;

    SPCTRM_SCN_DBG_FILE("\nAP THREAND START");
    while (1) {
        sem_wait(&g_semaphore);
        if (g_status == SCAN_BUSY) {
            spctrm_scn_wireless_set_status();
            /* timestamp */
            g_current_time = time(NULL);
            SPCTRM_SCN_DBG_FILE("\nAP SCAN START");
            spctrm_scn_wireless_channel_info(&current_channel_info,PLATFORM_5G);
            spctrm_scn_wireless_change_bw(BW_20);
            spctrm_scn_wireless_set_current_channel_info(&current_channel_info);
            sleep(5);
            memset(realtime_channel_info_5g,0,sizeof(realtime_channel_info_5g));
            for (g_scan_schedule = 0,j = 0,i = 0; i < sizeof(uint64_t) * ONE_BYTE; i++) {
                if ((g_input.channel_bitmap& (((uint64_t)1)<< i)) != 0) {
                    if (g_scan_schedule < g_input.channel_num - 1) {
                        pthread_mutex_lock(&g_scan_schedule_mutex);
                        g_scan_schedule++;
                        pthread_mutex_unlock(&g_scan_schedule_mutex);
                    }

                    realtime_channel_info_5g[j].channel = bitmap_to_channel(i);

                    SPCTRM_SCN_DBG_FILE("\nchange to channel : %d",realtime_channel_info_5g[j].channel);
                    if (spctrm_scn_wireless_change_channel(realtime_channel_info_5g[j].channel) == FAIL) {
                        goto error;
                    }

                    channel_scan(&realtime_channel_info_5g[j],g_input.scan_time);

                    sprintf(rlog_str,"{ \\\"channel\\\":\\\"%d\\\" }",realtime_channel_info_5g[j].channel);
                    sprintf(temp,"ubus call rlog upload_stream '{\"module_name\":\"spectrumScan\",\"server\":\"http://apidemo.rj.link/service/api/warnlog?sn=MACCEG20WJL01\",\"data\":\"%s\"}'",rlog_str);
                    SPCTRM_SCN_DBG_FILE("\n%s",temp);
                    system(temp);
                    memset(rlog_str,0,sizeof(rlog_str));
                    memset(temp,0,sizeof(temp));

                    SPCTRM_SCN_DBG_FILE("\ng_input.channel_bitmap : %llu",g_input.channel_bitmap);
                    realtime_channel_info_5g[j].score = spctrm_scn_wireless_channel_score(&realtime_channel_info_5g[j]);
                    realtime_channel_info_5g[j].rate = realtime_channel_info_5g[j].score / 100 * 300 * 0.75;
                    SPCTRM_SCN_DBG_FILE("\nscore %f\r\n",realtime_channel_info_5g[j].score);
                    SPCTRM_SCN_DBG_FILE("\n------------------\r\n");
                    j++;
                }
            }

            spctrm_scn_wireless_change_bw(current_channel_info.bw);

            if (spctrm_scn_wireless_change_channel(current_channel_info.channel) == FAIL) {
                goto error;
            }

            spctrm_scn_dev_reset_stat(&g_device_list);
            /* find AP */
            i = spctrm_scn_dev_find_ap(&g_device_list);
            g_device_list.device[i].finished_flag = FINISHED;
            if (timeout_func() == FAIL) {
                SPCTRM_SCN_DBG_FILE( "line : %d func %s g_status : %d,",__LINE__,__func__,g_status);
                memcpy(g_channel_info_5g,realtime_channel_info_5g,sizeof(realtime_channel_info_5g));

                pthread_mutex_lock(&g_finished_device_list_mutex);
                memcpy(&g_finished_device_list,&g_device_list,sizeof(struct device_list));
                SPCTRM_SCN_DBG_FILE("\ng_finished_device_list.list_len %d",g_finished_device_list.list_len);
                pthread_mutex_unlock(&g_finished_device_list_mutex);

                spctrm_scn_common_cmd("dev_sta get -m spectrumScan '{\"real_time\":false}'",NULL);

                pthread_mutex_lock(&g_mutex);
                SPCTRM_SCN_DBG_FILE("\ng_finished_device_list.list_len %d",g_finished_device_list.list_len);
                g_status = SCAN_TIMEOUT;
                g_input.scan_time = MIN_SCAN_TIME; /* restore scan time */
                pthread_mutex_unlock(&g_mutex);

                pthread_mutex_lock(&g_scan_schedule_mutex);
                g_scan_schedule++;
                pthread_mutex_unlock(&g_scan_schedule_mutex);
            } else {
                SPCTRM_SCN_DBG_FILE( "line : %d func %s g_status : %d,",__LINE__,__func__,g_status);
                memcpy(g_channel_info_5g,realtime_channel_info_5g,sizeof(realtime_channel_info_5g));

                pthread_mutex_lock(&g_finished_device_list_mutex);
                memcpy(&g_finished_device_list,&g_device_list,sizeof(struct device_list));
                SPCTRM_SCN_DBG_FILE("\ng_finished_device_list.list_len %d",g_finished_device_list.list_len);
                pthread_mutex_unlock(&g_finished_device_list_mutex);

                spctrm_scn_common_cmd("dev_sta get -m spectrumScan '{\"real_time\":false}'",NULL);

                pthread_mutex_lock(&g_mutex);
                SPCTRM_SCN_DBG_FILE("\ng_finished_device_list.list_len %d",g_finished_device_list.list_len);
                g_status = SCAN_IDLE;

                g_input.scan_time = MIN_SCAN_TIME; /* restore scan time */
                pthread_mutex_unlock(&g_mutex);

                pthread_mutex_lock(&g_scan_schedule_mutex);
                g_scan_schedule++;
                pthread_mutex_unlock(&g_scan_schedule_mutex);
            }
            system("dev_sta get -m spectrumScan");
            spctrm_scn_wireless_set_status();
error:
            pthread_mutex_lock(&g_mutex);
            g_status = SCAN_ERR;
            g_input.scan_time = MIN_SCAN_TIME; /* restore scan time */
            pthread_mutex_unlock(&g_mutex);
        }
    }
}

void *spctrm_scn_wireless_cpe_scan_thread()
{
    char *json_str;
    int i,j,len;
    double score;
    struct channel_info current_channel_info;

    SPCTRM_SCN_DBG_FILE("\nCPE THREAND START");
    while (1) {
        sem_wait(&g_semaphore);

        if (g_status == SCAN_BUSY) {
            /* timestamp */
            SPCTRM_SCN_DBG_FILE("\nCPE SCAN START");
            spctrm_scn_wireless_channel_info(&current_channel_info,PLATFORM_5G);
            spctrm_scn_wireless_change_bw(BW_20);
            sleep(5);
            memset(realtime_channel_info_5g,0,sizeof(realtime_channel_info_5g));
            for (j = 0,i = 0; i < sizeof(uint64_t) * ONE_BYTE; i++) {
                if ((g_input.channel_bitmap & (((uint64_t)1)<< i)) != 0) {

                    realtime_channel_info_5g[j].channel = bitmap_to_channel(i);
                    SPCTRM_SCN_DBG_FILE("\nchange channel to %d ",realtime_channel_info_5g[j].channel);

                    if (spctrm_scn_wireless_change_channel(realtime_channel_info_5g[j].channel) == FAIL) {
                        goto error;
                    }

                    channel_scan(&realtime_channel_info_5g[j],g_input.scan_time);

                    SPCTRM_SCN_DBG_FILE("\n%llu\r\n",g_input.channel_bitmap);
                    realtime_channel_info_5g[j].score = spctrm_scn_wireless_channel_score(&realtime_channel_info_5g[j]);
                    realtime_channel_info_5g[j].rate = realtime_channel_info_5g[j].score / 100 * 300 * 0.75;
                    SPCTRM_SCN_DBG_FILE("\n------------------\r\n");
                    j++;
                }

                if (g_status == SCAN_TIMEOUT) {
                    goto error;
                }
            }

            spctrm_scn_wireless_change_bw(current_channel_info.bw);
            if (spctrm_scn_wireless_change_channel(current_channel_info.channel) == FAIL) {
                goto error;
            }

            pthread_mutex_lock(&g_mutex);
            memcpy(g_channel_info_5g,realtime_channel_info_5g,sizeof(realtime_channel_info_5g));
            memset(realtime_channel_info_5g,0,sizeof(realtime_channel_info_5g));
            g_status = SCAN_IDLE;
            g_input.scan_time = MIN_SCAN_TIME; /* restore scan time */
            pthread_mutex_unlock(&g_mutex);
        }
error:
    if (g_status == SCAN_TIMEOUT) {
            spctrm_scn_wireless_change_bw(current_channel_info.bw);
            spctrm_scn_wireless_change_channel(current_channel_info.channel);
            pthread_mutex_lock(&g_mutex);
            g_status = SCAN_IDLE;
            g_input.scan_time = MIN_SCAN_TIME; /* restore scan time */
            memset(realtime_channel_info_5g,0,sizeof(realtime_channel_info_5g));
            pthread_mutex_unlock(&g_mutex);
        }
    }
}

static int quick_select(int* arr, int len, int k)
{
    int pivot, i, j, tmp;

    pivot = arr[len / 2];
    for (i = 0, j = len - 1;; i++, j--) {
        while (arr[i] < pivot) {
            i++;
        }

        while (arr[j] > pivot) {
            j--;
        }

        if (i >= j) {
            break;
        }

        tmp = arr[i];
        arr[i] = arr[j];
        arr[j] = tmp;
    }

    if (i == k - 1) {
        return pivot;
    }
    if (i < k - 1) {
        return quick_select(arr + i, len - i, k - i);
    }

    return quick_select(arr, i, k);
}


static int median(int* arr, int len)
{
    int median;

    if (len % 2 == 0) {
        median = (quick_select(arr, len, len / 2) + quick_select(arr, len, len / 2 + 1)) / 2;
    } else {
        median = quick_select(arr, len, len / 2 + 1);
    }

    return median;
}

int spctrm_scn_wireless_channel_info(struct channel_info *info,int band)
{
    char *rbuf;
    char *p;
    char cmd[MAX_POPEN_BUFFER_SIZE];

    if (info == NULL) {
         return FAIL;
    }

    if (band == PLATFORM_5G) {
        sprintf(cmd,"wlanconfig %s radio",g_wds_bss);
        spctrm_scn_common_cmd(cmd,&rbuf);

    } else if (band == PLATFORM_2G) {
        return FAIL;
    } else {
        return FAIL;
    }


    strtok(rbuf,"\n");

    strtok(NULL,":");
    p = strtok(NULL,"\n");
    if (p == NULL) {
        free(rbuf);
        return FAIL;
    }

    info->channel=atoi(p);

    strtok(NULL,":");
    p = strtok(NULL,"\n");
    if (p == NULL) {
        free(rbuf);
        return FAIL;
    }
    info->floornoise=atoi(p);

    strtok(NULL,":");
    p = strtok(NULL,"\n");
    if (p == NULL) {
        free(rbuf);
        return FAIL;
    }
    info->utilization=atoi(p);

    strtok(NULL,"\n");
    strtok(NULL,":");
    p = strtok(NULL,"\n");
    if (p == NULL) {
        free(rbuf);
        return FAIL;
    }
    info->bw = atoi(p);

    strtok(NULL,":");
    p = strtok(NULL,"\n");
    if (p == NULL) {
        free(rbuf);
        return FAIL;
    }
    info->obss_util=atoi(p);

    strtok(NULL,":");
    p = strtok(NULL,"\n");
    if (p == NULL) {
        free(rbuf);
        return FAIL;
    }
    info->tx_util=atoi(p);

    strtok(NULL,":");

    p = strtok(NULL,"\n");
    if (p == NULL) {
        free(rbuf);
        return FAIL;
    }

    info->rx_util=atoi(p);

    free(rbuf);

    return SUCCESS;
}

void channel_scan(struct channel_info *input,int scan_time)
{
    json_object *root;
    int i,err_count;
    struct channel_info info[MAX_SCAN_TIME];
    int utilization_temp[MAX_SCAN_TIME];
    int obss_util_temp[MAX_SCAN_TIME];
    int floornoise_temp[MAX_SCAN_TIME];
    int channel_temp[MAX_SCAN_TIME];
    time_t timestamp[MAX_SCAN_TIME];
    struct tm *local_time;

    if (input == NULL) {
        SPCTRM_SCN_DBG_FILE("\nparam error");
        return;
    }
    if (scan_time > MAX_SCAN_TIME) {
        scan_time = MAX_SCAN_TIME;
    }

    if (scan_time < MIN_SCAN_TIME) {
        scan_time = MIN_SCAN_TIME;
    }

    err_count = 0;
    for (i = 0 ;i < scan_time ;i++) {
        // sleep(1);
        spctrm_scn_wireless_channel_info(&info[i],PLATFORM_5G);
        timestamp[i] = time(NULL);
        SPCTRM_SCN_DBG_FILE("\ncurrent channel %d",info[i].channel);
    }

    input->bw=info[0].bw;


    for (i = 0 ;i < scan_time ;i++) {

        channel_temp[i] = info[i].channel;
        if (info[i].channel == info[0].channel) {
            floornoise_temp[i] = info[i].floornoise;
            utilization_temp[i] = info[i].utilization;
            obss_util_temp[i] = info[i].obss_util;
        } else {
            err_count++;
        }
    }

    input->floornoise = median(floornoise_temp,scan_time - err_count);
    input->utilization = median(utilization_temp,scan_time - err_count);
    input->obss_util = median(obss_util_temp,scan_time - err_count);

    SPCTRM_SCN_DBG_FILE("\ng_status %d",g_status);

    return;
}



void spctrm_scn_wireless_wds_state()
{
    char *rbuf;
    json_object *rbuf_root;
    json_object *role_obj;

    if (spctrm_scn_common_cmd("dev_sta get -m wds_status", &rbuf) == FAIL) {
        SPCTRM_SCN_DBG_FILE("\ncmd fail");
        return;
    }
    rbuf_root = json_tokener_parse(rbuf);
    if (rbuf_root == NULL) {
        free(rbuf);
        return;
    }
    role_obj = json_object_object_get(rbuf_root,"role");
    if (role_obj == NULL) {
        goto clear;
    }
    if (strcmp(json_object_get_string(role_obj),"cpe") == 0) {
        g_mode = CPE_MODE;
    } else if (strcmp(json_object_get_string(role_obj),"ap") == 0) {
        g_mode = AP_MODE;
    }
clear:
    free(rbuf);
    json_object_put(rbuf_root);
    SPCTRM_SCN_DBG_FILE("\ng_mode %d",g_mode);
}

static double calculate_N(struct channel_info *info)
{
    double N;

    if (info == NULL) {
        return FAIL;
    }

    if (info->floornoise <= -87) {
        N = 0;
    } else if ( -87 < info->floornoise && info->floornoise <= -85) {
        N = 1;
    } else if (-85 < info->floornoise && info->floornoise <= -82) {
        N = 2;
    } else if (-82 < info->floornoise && info->floornoise <= -80) {
        N = 2.8;
    } else if (-80 < info->floornoise && info->floornoise <= -76) {
        N = 4;
    } else if (-76 < info->floornoise && info->floornoise <= -71) {
        N = 4.8;
    } else if (-71 < info->floornoise && info->floornoise <= -69) {
        N = 5.2;
    } else if (-69 < info->floornoise && info->floornoise <= -66) {
        N = 6.4;
    } else if (-66 < info->floornoise && info->floornoise <= -62) {
        N = 7.6;
    } else if (-62 < info->floornoise && info->floornoise <= -60) {
        N = 8.2;
    } else if (-60 < info->floornoise && info->floornoise <= -56) {
        N = 8.8;
    } else if (-56 < info->floornoise && info->floornoise <= -52) {
        N = 9.4;
    } else if (-52 < info->floornoise ) {
        N = 10;
    }

    return N;
}

double spctrm_scn_wireless_channel_score(struct channel_info *info)
{
    double N;

    if (info == NULL) {
        SPCTRM_SCN_DBG_FILE("\ninfo NULL");
        return FAIL;
    }

    N = calculate_N(info);
    if (N == FAIL) {
        return FAIL;
    }

    return ((double)1 - N/20)*(double)((double)1 - (double)info->obss_util / 95) * 100;/* bw20公式 */
}
void spctrm_scn_wireless_bw40_channel_score (struct device_info *device)
{
    int j;
    int bw;
    uint64_t bitmap_2G,bitmap_5G;

    if (device == NULL) {
        SPCTRM_SCN_DBG_FILE("\nparam NULL");
        return;
    }



    SPCTRM_SCN_DBG_FILE("\ng_input.channel_num %d ",g_bw40_channel_num);
    for (j = 0; j < g_bw40_channel_num / 2; j++) {
        device->bw40_channel[j] = device->channel_info[2 * j];
        SPCTRM_SCN_DBG_FILE("\nbw40_channel %d",device->bw40_channel[j].channel);
        /* bw40底噪 */
        device->bw40_channel[j].floornoise = MAX(device->channel_info[2 * j].floornoise, device->channel_info[2 * j + 1].floornoise);
        /* bw40得分公式 */
        device->bw40_channel[j].score = ((double)1 - calculate_N(&(device->bw40_channel[j])) / 20) *
                                        (double)((double)1 - (double)(device->channel_info[2 * j].obss_util +
                                                                      device->channel_info[2 * j + 1].obss_util) / (95 * BW_40 / 20)) * 100;
        device->bw40_channel[j].rate = device->bw40_channel[j].score /100 * 600 * 0.75;/* bw40公式 */
        device->bw40_channel[j].score = device->bw40_channel[j].score; /* 干扰得分 */
    }
}
void spctrm_scn_wireless_bw80_channel_score (struct device_info *device)
{
    int j;
    int bw;
    uint64_t bitmap_2G,bitmap_5G;

    if (device == NULL) {
        SPCTRM_SCN_DBG_FILE("\nparam error");
        return ;
    }

    for (j = 0; j < g_bw80_channel_num; j++) {
        device->bw80_channel[j] = device->channel_info[4 * j];
        /* bw80底噪 */
        device->bw80_channel[j].floornoise = MAX(MAX(MAX(device->channel_info[4 * j].floornoise,
                                                        device->channel_info[4 * j + 1].floornoise),
                                                         device->channel_info[4 * j + 2].floornoise),
                                                         device->channel_info[4 * j + 3].floornoise);
        /* bw80得分公式 */
        device->bw80_channel[j].score = ((double)1 - calculate_N(&(device->bw80_channel[j])) / 20) *
                                        (double)((double)1 - (double)(device->channel_info[4 * j].obss_util +
                                        device->channel_info[4 * j + 1].obss_util +
                                        device->channel_info[4 * j + 2].obss_util +
                                        device->channel_info[4 * j + 3].obss_util) / (95 * BW_80 / 20)) * 100;
        device->bw80_channel[j].rate = device->bw80_channel[j].score /100 * 1200 * 0.75;

        device->bw80_channel[j].score = device->bw80_channel[j].score; /* 干扰得分 */
    }
}


static int timeout_func()
{
    int i,j;

    for (j = 0; j < 30;j++) {
        SPCTRM_SCN_DBG_FILE("\nwait %d",j);
        sleep(1);
        if (spctrm_scn_tipc_send_auto_get_msg(&g_device_list,3) == SUCCESS) {
            return SUCCESS;
        }
    }
    return FAIL;
}

inline int spctrm_scn_wireless_channel_check(int channel)
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

#ifdef POPEN_CMD_ENABLE
int spctrm_scn_wireless_change_channel(int channel)
{
    char cmd[MAX_POPEN_BUFFER_SIZE];
    if (spctrm_scn_wireless_channel_check(channel) == FAIL) {
        SPCTRM_SCN_DBG_FILE("\nparam error");
        return FAIL;
    }

    sprintf(cmd,"iwpriv %s set  channel=%d",g_wds_bss,channel);

    spctrm_scn_common_cmd(cmd,NULL);

    return SUCCESS;
}
#elif defined UNIFY_FRAMEWORK_ENABLE
int spctrm_scn_wireless_change_channel(int channel)
{
    uf_cmd_msg_t *msg_obj;
    int ret;
    char* rbuf;
    char param[100];

    if (spctrm_scn_wireless_channel_check(channel) == FAIL) {
        SPCTRM_SCN_DBG_FILE("\nparam error");
        return FAIL;
    }

    sprintf(param,"{\"radioList\": [ { \"radioIndex\": \"1\", \"type\":\"5G\", \"channel\":\"%d\" }]}",channel);
    SPCTRM_SCN_DBG_FILE("\n%s\r\n",param);
    msg_obj = (uf_cmd_msg_t*)malloc(sizeof(uf_cmd_msg_t));
    if (msg_obj == NULL) {
        return -1;
    }
    memset(msg_obj, 0, sizeof(uf_cmd_msg_t));
    msg_obj->ctype = UF_DEV_CONFIG_CALL;/* 调用类型 ac/dev/.. */
    msg_obj->param = param;
    msg_obj->cmd = "update";
    msg_obj->module = "radio";             /* 必填参数，其它可选参数根据需要使用 */
    msg_obj->caller = "group_change";   /* 自定义字符串，标记调用者 */
    ret = uf_client_call(msg_obj, &rbuf, NULL);
    if (ret == FAIL) {
        json_object_put(input_param_root);
        return FAIL;
    }
    if (rbuf) {
      free(rbuf);
    }
    free(msg_obj);
}
#endif
