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
	for (i = 0;i < device_list->list_len;i++) {
		if (strcmp(device_list->device[i].role,"ap") == 0) {
			return i;
		}
	}
}
void spctrm_scn_dev_reset_stat(struct device_list *list) {
	struct device_info *p;
	int i;
	list_for_each_device(p, i, list) {
		p->finished_flag = NOT_FINISH;
	}
}

int show_device_info(struct device_info *device_info) {
	int i;
	debug("show info");
	printf(" series_no %s\r\n",device_info->series_no);
	for (i = 0; i < g_input.channel_num;i++) {
		printf("\r\n");
		printf(" channel %d\r\n",device_info->channel_info[i].channel);
		printf(" floornoise %d\r\n",device_info->channel_info[i].floornoise);
		printf(" obss_util %d\r\n",device_info->channel_info[i].obss_util);
		printf(" score %f\r\n",device_info->channel_info[i].score);
		printf("\r\n");
	}
	
}

int spctrm_scn_dev_find_by_sn(struct device_list *device_list,char *series_no)
{
	int i;

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
	list_for_each_device(p, i, device_list) {
		debug("p->finished_flag %d",p->finished_flag);
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
	int i;

	json_object *rbuf_root;
	json_object *list_all_obj;
	json_object *list_pair_obj;
	json_object *sn_obj,*role_obj,*mac_obj;
	json_object *list_all_elem ;
	
	spctrm_scn_common_cmd("dev_sta get -m wds_list_all",&rbuf);

	rbuf_root = json_tokener_parse(rbuf);
	list_all_obj = json_object_object_get(rbuf_root,"list_all");
	debug("");
	spctrm_scn_common_get_sn(sn);
	debug("%s",sn);
	// for (i = 0;i < json_object_array_length(list_all_obj);i++) {
	// 	list_all_elem = json_object_array_get_idx(list_all_obj,i);
	// }
	list_all_elem = json_object_array_get_idx(list_all_obj,0);
	debug("");
	list_pair_obj = json_object_object_get(list_all_elem,"list_pair");
	debug("");
	device_list->list_len = json_object_array_length(list_pair_obj);

	for (i = 0;i < json_object_array_length(list_pair_obj);i++) {
		json_object *list_pair_elem;
		list_pair_elem = json_object_array_get_idx(list_pair_obj,i);
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
