#include "spctrm_scn_rlog.h"

pthread_mutex_t g_rlog_server_addr_mutex;
char g_rlog_server_addr[MAX_RLOG_SERVER_ADDR_LEN];


void spctrm_scn_rlog_init()
{
    pthread_mutex_init(&g_rlog_server_addr_mutex,NULL);
}
int spctrm_scn_rlog_get_module_enable()
{
    char *rbuf;
    json_object *root,*result_obj;
    spctrm_scn_common_cmd("dev_sta get -m rlog_module_enable '{\"module\":\"spectrumScan\"}'",&rbuf);

    root = json_tokener_parse(rbuf);
    if (root == NULL) {
        if (rbuf != NULL) {
            free(rbuf);
        }
        return FAIL;
    }

    result_obj = json_object_object_get(root,"result");
    if (result_obj == NULL) {
        if (rbuf != NULL) {
            free(rbuf);
        }
        json_object_put(root);
        return FAIL;
    }

    if (strcmp(json_object_get_string(result_obj),"0") == 0) {
        if (rbuf != NULL) {
            free(rbuf);
        }
        json_object_put(root);
        return RLOG_DISABLE;
    } else if (strcmp(json_object_get_string(result_obj),"1") == 0) {
        if (rbuf != NULL) {
            free(rbuf);
        }
        json_object_put(root);
        return RLOG_ENABLE;
    } else {
        if (rbuf != NULL) {
            free(rbuf);
        }
        json_object_put(root);
        return FAIL;        
    }
}
void spctrm_scn_rlog_get_server_addr()
{
    FILE *fp;
    int fd,len;
    char *rbuf;
    json_object *rbuf_root,*server_obj;

    if (access("/etc/spectrum_scan/rlog_server_addr.json",F_OK) == FAIL) {
        fd = creat("/etc/spectrum_scan/rlog_server_addr.json",0777);
        if (fd < 0) {
            return;
        }
        close(fd);
    }

    spctrm_scn_common_cmd("dev_config get -m rlog_config",&rbuf);

    SPCTRM_SCN_DBG_FILE("%s",rbuf);
    rbuf_root = json_tokener_parse(rbuf);
    if (rbuf_root == NULL) {
        if (rbuf != NULL) {
            free(rbuf);
        }
        return;
    }

    server_obj = json_object_object_get(rbuf_root,"server");
    if (server_obj == NULL) {
        if (rbuf != NULL) {
            free(rbuf);
        }
        json_object_put(rbuf_root);
        return;
    }

    len = json_object_get_string_len(server_obj);
    if (len > MAX_RLOG_SERVER_ADDR_LEN) {
        if (rbuf != NULL) {
            free(rbuf);
        }
        json_object_put(rbuf_root);
        return;
    }

    pthread_mutex_lock(&g_rlog_server_addr_mutex);
    strncpy(g_rlog_server_addr,json_object_get_string(server_obj),len);
    pthread_mutex_unlock(&g_rlog_server_addr_mutex);

    SPCTRM_SCN_DBG_FILE("%s",g_rlog_server_addr);

    fp = fopen("/etc/spectrum_scan/rlog_server_addr.json","w");
    if (fp == NULL) {
        if (rbuf != NULL) {
            free(rbuf);
        }
        json_object_put(rbuf_root);
        return;
    }
    pthread_mutex_lock(&g_rlog_server_addr_mutex);
    fprintf(fp,"%s",g_rlog_server_addr);
    pthread_mutex_unlock(&g_rlog_server_addr_mutex);

    fclose(fp);

    if (rbuf != NULL) {
        free(rbuf);
    }
    json_object_put(rbuf_root);
}


void spctrm_scn_rlog_get_module_server_addr()
{
    FILE *fp;
    int fd,len;
    char *rbuf,sn[SN_LEN];
    json_object *rbuf_root,*module_list_obj,*module_list_elem_obj,*module_name_obj,*server_obj;
    int i,list_len;
    
    if (access("/etc/spectrum_scan/rlog_server_addr.json",F_OK) == FAIL) {
        fd = creat("/etc/spectrum_scan/rlog_server_addr.json",0777);
        if (fd < 0) {
            return;
        }
        close(fd);
    }

    spctrm_scn_common_cmd("dev_config get -m rlog_module_config",&rbuf);

    SPCTRM_SCN_DBG_FILE("%s",rbuf);
    rbuf_root = json_tokener_parse(rbuf);
    if (rbuf_root == NULL) {
        if (rbuf != NULL) {
            free(rbuf);
        }
        return;
    }
    module_list_obj = json_object_object_get(rbuf_root,"module_list");
    if (module_list_obj == NULL) {
        if (rbuf != NULL) {
            free(rbuf);
        }
        json_object_put(rbuf_root);
        SPCTRM_SCN_DBG_FILE("FAIL\r\n");
        return;
    }
    list_len = json_object_array_length(module_list_obj);
    for (i = 0;i < list_len;i++) {
        SPCTRM_SCN_DBG_FILE("%d\r\n",i);
        module_list_elem_obj = json_object_array_get_idx(module_list_obj,i);
        module_name_obj = json_object_object_get(module_list_elem_obj,"module_name");
        if (module_name_obj == NULL) {
            SPCTRM_SCN_DBG_FILE("NULL\r\n");
            continue;
        }
        if (strcmp("spectrumScan",json_object_get_string(module_name_obj)) == 0) {
            server_obj = json_object_object_get(module_list_elem_obj,"server");
            if (server_obj == NULL) {
                if (rbuf != NULL) {
                    free(rbuf);
                }
                json_object_put(rbuf_root);
                SPCTRM_SCN_DBG_FILE("FAIL\r\n");
                return;
            }

            len = json_object_get_string_len(server_obj);
            if (len + SN_LEN > MAX_RLOG_SERVER_ADDR_LEN) {
                if (rbuf != NULL) {
                    free(rbuf);
                }
                json_object_put(rbuf_root);
                SPCTRM_SCN_DBG_FILE("FAIL\r\n");
                return;
            }

            pthread_mutex_lock(&g_rlog_server_addr_mutex);
            strncpy(g_rlog_server_addr,json_object_get_string(server_obj),len);
            pthread_mutex_unlock(&g_rlog_server_addr_mutex);

            spctrm_scn_common_get_sn(sn);
            sprintf(g_rlog_server_addr,"%s?sn=%s",g_rlog_server_addr,sn);
            SPCTRM_SCN_DBG_FILE("%s\r\n",g_rlog_server_addr);
            fp = fopen("/etc/spectrum_scan/rlog_server_addr.json","w");
            if (fp == NULL) {
                if (rbuf != NULL) {
                    free(rbuf);
                }
                json_object_put(rbuf_root);
                return;
            }
            pthread_mutex_lock(&g_rlog_server_addr_mutex);
            fprintf(fp,"%s",g_rlog_server_addr);
            pthread_mutex_unlock(&g_rlog_server_addr_mutex);

            fclose(fp);
            break;
        }
    }

    if (rbuf != NULL) {
        free(rbuf);
    }
    json_object_put(rbuf_root);
}

