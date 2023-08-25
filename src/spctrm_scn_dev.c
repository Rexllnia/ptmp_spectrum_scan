#include "spctrm_scn_dev.h"

extern struct user_input g_input;
extern int g_status;
int spctrm_scn_dev_list_cmp(struct device_list *src_list,struct device_list *dest_list) {
    int i,count;
    struct device_info *p;
    count = 0;

    if (src_list == NULL || dest_list == NULL) {
        return FAIL;
    }

    list_for_each_device(p, i, src_list) {
        if (spctrm_scn_dev_find_by_sn(dest_list, p->series_no) == FAIL) {
            count++;
        }
    }

    return count;
}

struct device_info *spctrm_scn_dev_find_ap2(struct device_list *device_list)
{
    struct device_info *p;
    int i;

    if (device_list == NULL) {
        return NULL;
    }

    list_for_each_device(p,i,device_list) {
        if (strcmp(device_list->device[i].role,"ap") == 0) {
            return p;
        }
    }
}
int spctrm_scn_dev_find_ap(struct device_list *device_list)
{
    int i;

    if (device_list == NULL) {
        return FAIL;
    }

    for (i = 0;i < device_list->list_len;i++) {
        if (strcmp(device_list->device[i].role,"ap") == 0) {
            return i;
        }
    }
    return FAIL;
}

void spctrm_scn_dev_reset_stat(struct device_list *list) {
    struct device_info *p;
    int i;

    if (list == NULL) {
        return;
    }
    list_for_each_device(p, i, list) {
        p->finished_flag = NOT_FINISH;
    }
}

int spctrm_scn_dev_find_by_sn(struct device_list *device_list,char *series_no)
{
    int i;

    if (device_list == NULL || series_no == NULL) {
        return FAIL;
    }

    for (i = 0;i < device_list->list_len;i++) {
        if (strcmp(device_list->device[i].series_no,series_no) == 0) {
            return i;
        }
    }
    return FAIL;
}
int spctrm_scn_dev_chk_stat(struct device_list *device_list) {

    struct device_info *p;
    int i;

    if (device_list == NULL) {
        return FAIL;
    }

    list_for_each_device(p, i, device_list) {
        SPCTRM_SCN_DBG_FILE("\nmac:%x p->finished_flag %d",p->mac,p->finished_flag);
        if (p->finished_flag == NOT_FINISH) {
            return FAIL;
        }
    }

    return SUCCESS;
}

int spctrm_scn_dev_wds_list(struct device_list *device_list)
{
    char *rbuf;
    char sn[SN_LEN];
    int i,j,find_flag;
    json_object *rbuf_root;
    json_object *list_all_obj;
    json_object *list_pair_obj;
    json_object *sn_obj,*role_obj,*mac_obj,*rssi_obj,*dev_type_obj,*wan_speed_cap_obj,*user_ip_obj;
    json_object *list_all_elem ;
    json_object *list_pair_elem;

    if (device_list == NULL) {
        SPCTRM_SCN_DBG_FILE("\ndevice_list NULL");
        return FAIL;
    }

    spctrm_scn_common_cmd("dev_sta get -m wds_list_all",&rbuf);

    rbuf_root = json_tokener_parse(rbuf);
    if (rbuf_root == NULL) {
        perror("rbuf_root");
        return FAIL;
    }
    list_all_obj = json_object_object_get(rbuf_root,"list_all");
    if (list_all_obj == NULL) {
        perror("list_all_obj");
        free(rbuf);
        json_object_put(rbuf_root);
        return FAIL;
    }

    SPCTRM_SCN_DBG_FILE("\n");
    spctrm_scn_common_get_sn(sn);
    SPCTRM_SCN_DBG_FILE("\nsn %s",sn);

    find_flag = 0;
    for (i = 0;i < json_object_array_length(list_all_obj);i++) {
        list_all_elem = json_object_array_get_idx(list_all_obj,i);
        if (list_all_elem == NULL) {
            perror("list_all_obj");
            free(rbuf);
            json_object_put(rbuf_root);
            return FAIL;
        }

        list_pair_obj = json_object_object_get(list_all_elem,"list_pair");
        if (list_pair_obj == NULL) {
            perror("list_all_elem");
            free(rbuf);
            json_object_put(rbuf_root);
            return FAIL;
        }

        for (j = 0;j < json_object_array_length(list_pair_obj);j++) {
            list_pair_elem = json_object_array_get_idx(list_pair_obj,j);
            if (list_pair_elem == NULL) {
                perror("list_pair_elem");
                free(rbuf);
                json_object_put(rbuf_root);
                return FAIL;
            }
            sn_obj = json_object_object_get(list_pair_elem,"sn");
            if (sn_obj == NULL) {
                perror("sn_obj");
                free(rbuf);
                json_object_put(rbuf_root);
                return FAIL;
            }

            SPCTRM_SCN_DBG_FILE("SN %s \r\n",json_object_get_string(sn_obj));
            if (strcmp(json_object_get_string(sn_obj),sn) == 0) {
                SPCTRM_SCN_DBG_FILE("\n%d",i);
                find_flag = 1;
                break;
            }
        }
        if (find_flag == 1) {
            break;
        }
    }
    SPCTRM_SCN_DBG_FILE("\n%d",i);

    list_all_elem = json_object_array_get_idx(list_all_obj,i);
    if (list_all_elem == NULL) {
        free(rbuf);
        json_object_put(rbuf_root);
        perror("list_all_elem");
        return FAIL;
    }
    list_pair_obj = json_object_object_get(list_all_elem,"list_pair");
    if (list_pair_obj == NULL) {
        free(rbuf);
        json_object_put(rbuf_root);
        SPCTRM_SCN_DBG_FILE("\nlist_pair_obj");
        return FAIL;
    }
    device_list->list_len = json_object_array_length(list_pair_obj);

    if (device_list->list_len > MAX_DEVICE_NUM) {
        free(rbuf);
        json_object_put(rbuf_root);
        SPCTRM_SCN_DBG_FILE("\nover MAX_DEVICE_NUM");
        return FAIL;
    }

    for (i = 0;i < device_list->list_len;i++) {
        list_pair_elem = json_object_array_get_idx(list_pair_obj,i);
        sn_obj = json_object_object_get(list_pair_elem,"sn");

        if (sn_obj == NULL) {
            free(rbuf);
            json_object_put(rbuf_root);
            SPCTRM_SCN_DBG_FILE("\nsn_obj");
            return FAIL;
        }
        SPCTRM_SCN_DBG_FILE("SN %s \r\n",json_object_get_string(sn_obj));

        role_obj = json_object_object_get(list_pair_elem,"role");
        if (role_obj == NULL) {
            free(rbuf);
            json_object_put(rbuf_root);
            SPCTRM_SCN_DBG_FILE("\nrole_obj");
            return FAIL;
        }
        SPCTRM_SCN_DBG_FILE("ROLE %s \r\n",json_object_get_string(role_obj));
        mac_obj = json_object_object_get(list_pair_elem,"mac");
        if (mac_obj == NULL) {
            free(rbuf);
            json_object_put(rbuf_root);
            SPCTRM_SCN_DBG_FILE("\nmac_obj");
            return FAIL;
        }
        strcpy(device_list->device[i].series_no,json_object_get_string(sn_obj));
        SPCTRM_SCN_DBG_FILE("SN %s \r\n",device_list->device[i].series_no);

        strcpy(device_list->device[i].role,json_object_get_string(role_obj));

        if (strcmp(json_object_get_string(role_obj),"ap") != 0) {
           rssi_obj = json_object_object_get(list_pair_elem,"rssi");
            if (json_object_get_string(rssi_obj) != NULL) {
           device_list->device[i].rssi = atoi(json_object_get_string(rssi_obj));
           SPCTRM_SCN_DBG_FILE("RSSI %d \r\n",device_list->device[i].rssi);
         }
        }

        dev_type_obj = json_object_object_get(list_pair_elem,"dev_type");
        if (dev_type_obj != NULL) {
            if (json_object_get_string(dev_type_obj) != NULL && json_object_get_string_len(dev_type_obj) < DEV_TYPE_STR_LEN) {
                strcpy(device_list->device[i].dev_type,json_object_get_string(dev_type_obj));
            }
        }

        wan_speed_cap_obj = json_object_object_get(list_pair_elem,"wanSpeedCap");
        if (wan_speed_cap_obj != NULL) {
            if (json_object_get_string(wan_speed_cap_obj) != NULL) {
                device_list->device[i].wan_speed_cap = atoi(json_object_get_string(wan_speed_cap_obj));
            }
        }
        user_ip_obj = json_object_object_get(list_pair_elem,"userIp");
        if (user_ip_obj != NULL) {
            if (json_object_get_string(user_ip_obj) != NULL) {
                memcpy(device_list->device[i].user_ip,json_object_get_string(user_ip_obj),IP_ADDR_LEN);
            }
        }
        SPCTRM_SCN_DBG_FILE("ROLE %s \r\n",device_list->device[i].role);

        strcpy(device_list->device[i].mac,json_object_get_string(mac_obj));

    }

    free(rbuf);
    json_object_put(rbuf_root);
    return SUCCESS;
}
