#include "spctrm_scn_common.h"


char spctrm_scn_common_read_file(char *name,char *buf,char len) {
    int fd;

    if (name == NULL || buf == NULL ) {
        return FAIL;
    }

    memset(buf,0,len);
    fd = open(name, O_RDONLY);
    if (fd > 0) {
        read(fd,buf,len);
        close(fd);
        if (buf[strlen(buf) - 1] == '\n') {
            buf[strlen(buf) - 1] = 0;
        }
        return SUCCESS;
    }
    return FAIL;
}
__u32 spctrm_scn_common_mac_2_nodeadd(unsigned char *mac_src)
{
    unsigned int mac[ETH_ALEN];
    unsigned int tmp;
    char buf[30];

    if (mac_src == NULL) {
        return 0;
    }

    memset(mac,0,sizeof(mac));
    if (sscanf(mac_src, "%2x:%2x:%2x:%2x:%2x:%2x",&mac[0],&mac[1],&mac[2],&mac[3],&mac[4],&mac[5]) != 6) {
        perror("please input right like :rg_tipc_mac_to_nodeadd aa:bb:cc:dd:ee:ffi \n");
        return 0;
    }

    tmp = (mac[0] ^ mac[1] ^ mac[2]) & 0xff;
    tmp = (tmp & 0x0f) ^ (tmp >> 4);

    memset(buf,0,sizeof(buf));
    sprintf(buf,"%x%02x%02x%02x",tmp,mac[3],mac[4],mac[5]);

    tmp = 0;
    sscanf(buf,"%x",&tmp);
    return tmp;
}
int spctrm_scn_common_cmd(char *cmd,char **rbuf) 
{
    FILE *fp;

    if (cmd == NULL) {
        return FAIL;
    }

    fp = popen(cmd, "r");
    if (fp == NULL) {
        return FAIL;
    }
    
    if (rbuf == NULL) {
        pclose(fp);
        return SUCCESS;
    }
    *rbuf =(char *) malloc(MAX_POPEN_BUFFER_SIZE);
    if (rbuf == NULL) {
        pclose(fp);
        return FAIL;
    }
    
    
    fread(*rbuf,sizeof(char),MAX_POPEN_BUFFER_SIZE,fp);
    pclose(fp);
    return SUCCESS;
}
void spctrm_scn_common_get_sn(char *sn)
{
    int ret;
    char res[SN_LEN];

    if (sn == NULL) {
        return ;
    }

    memset(res, 0, SN_LEN);
    ret = spctrm_scn_common_uci_anonymous_get("sysinfo", "sysinfo", "sysinfo", "serial_num", res, sizeof(res));
    if (ret != 0) {
        return;
    }


    strncpy(sn, res, SN_LEN);
    return;
}
int spctrm_scn_common_uci_anonymous_get(char *file, char *type, char *name, char *option, char *buf, int len)
{
    struct uci_context *ctx = NULL;
    struct uci_package *pkg = NULL;
    struct uci_section *sec = NULL;
    struct uci_element *ele = NULL;
    const char *str = NULL;
    char ret = FAIL;

    if (file == NULL) {
        return FAIL;
    }
    if (type == NULL) {
        return FAIL;
    }
    if (name == NULL) {
        return FAIL;
    }
    if (option == NULL) {
        return FAIL;
    }
    if (buf == NULL) {
        return FAIL;
    }
    if (len <= 0) {
        return FAIL;
    }

    ctx = uci_alloc_context();
    if (ctx == NULL) {
        return FAIL;
    }

    if (UCI_OK != uci_load(ctx, file, &pkg)) {
        ret = FAIL;
        goto cleanup;
    }


    uci_foreach_element(&pkg->sections, ele) {
        sec = uci_to_section(ele);
        if (strcmp(sec->type, name) != 0) {
            continue;
        }
        str = uci_lookup_option_string(ctx, sec, option);
        if (str != NULL) {
            strncpy(buf, str, len);
            ret = SUCCESS;
			break;							
        }
    }

    uci_unload(ctx, pkg);

cleanup:
    uci_free_context(ctx);
    ctx = NULL;

    return ret;
}
