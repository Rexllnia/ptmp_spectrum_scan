#include "spctrm_scn_dev.h"
#include "spctrm_scn_config.h"
#include <stdio.h>

extern struct user_input g_input;

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
        debug("mac:%x p->finished_flag %d",p->mac,p->finished_flag);
        if (p->finished_flag == NOT_FINISH) {
            return FAIL;
        }
    }

    return SUCCESS;
}
