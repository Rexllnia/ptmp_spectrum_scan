#include "spctrm_scn_dev.h"
#include "spctrm_scn_config.h"
#include <stdio.h>

extern struct user_input g_input;

int spctrm_scn_dev_list_cmp(struct device_list *src_list,struct device_list *dest_list) {

    int i,count;
    struct device_info *p;
    count = 0;

    list_for_each_device(p, i, src_list) {
        if (spctrm_scn_dev_find_by_sn(dest_list, p->series_no) == FAIL) {
            count++;
        }
    }

    return count;
}

int spctrm_scn_dev_modify(struct device_list *device_list,struct device_info *device)
{
    int pos;

    if (device_list == NULL || device == NULL) {
        return FAIL;
    } 

    pos = spctrm_scn_dev_find_by_sn(device_list,device->series_no);

    
    memcpy(&device_list[pos],device,sizeof(struct device_info));
     
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
}
void spctrm_scn_dev_reset_stat(struct device_list *list) {
	struct device_info *p;
	int i;

	if (list == NULL) {
		return FAIL;
	}
	list_for_each_device(p, i, list) {
		p->finished_flag = NOT_FINISH;
	}
}


int spctrm_scn_dev_find_by_sn(struct device_list *device_list,char *series_no)
{
	int i;

	if (device_list == NULL) {
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

void spctrm_scn_dev_wds_list(struct device_list *device_list)
{
	char *rbuf;
	char sn[SN_LEN];
	int i,j,find_flag;

	json_object *rbuf_root;
	json_object *list_all_obj;
	json_object *list_pair_obj;
	json_object *sn_obj,*role_obj,*mac_obj;
	json_object *list_all_elem ;
	json_object *list_pair_elem;

	if (device_list == NULL) {
		debug("device_list NULL");
		exit(0);
	}
	
	spctrm_scn_common_cmd("dev_sta get -m wds_list_all",&rbuf);

	rbuf_root = json_tokener_parse(rbuf);
	list_all_obj = json_object_object_get(rbuf_root,"list_all");
	debug("");
	spctrm_scn_common_get_sn(sn);
	debug("sn %s",sn);

	find_flag = 0;
	for (i = 0;i < json_object_array_length(list_all_obj);i++) {
		list_all_elem = json_object_array_get_idx(list_all_obj,i);
		list_pair_obj = json_object_object_get(list_all_elem,"list_pair");
		for (j = 0;j < json_object_array_length(list_pair_obj);j++) {
			list_pair_elem = json_object_array_get_idx(list_pair_obj,j);
			sn_obj = json_object_object_get(list_pair_elem,"sn");
			if (strcmp(json_object_get_string(sn_obj),sn) == 0) {
				debug("%d",i);
				find_flag = 1;
				break;
			}
		}
		if (find_flag == 1) {
			break;
		}
	}
	debug("%d",i);

	list_all_elem = json_object_array_get_idx(list_all_obj,i);
	debug("");
	list_pair_obj = json_object_object_get(list_all_elem,"list_pair");
	debug("");
	device_list->list_len = json_object_array_length(list_pair_obj);

	for (i = 0;i < json_object_array_length(list_pair_obj);i++) {
		list_pair_elem = json_object_array_get_idx(list_pair_obj,i);/* xxx */
		sn_obj = json_object_object_get(list_pair_elem,"sn");
		role_obj = json_object_object_get(list_pair_elem,"role");
		mac_obj = json_object_object_get(list_pair_elem,"mac");
		strcpy(device_list->device[i].series_no,json_object_get_string(sn_obj));
		strcpy(device_list->device[i].role,json_object_get_string(role_obj));
		strcpy(device_list->device[i].mac,json_object_get_string(mac_obj));
	}

	free(rbuf);
	json_object_put(rbuf_root);
}

