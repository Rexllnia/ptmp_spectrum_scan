#include "channel_scan.h"

struct user_input g_input;

struct device_list g_finished_device_list;
struct device_list g_device_list;
struct channel_info g_channel_info_5g[36];
struct channel_info realtime_channel_info_5g[36];

volatile int g_status,g_scan_time;
volatile long g_scan_timestamp;

long g_bitmap_2G,g_bitmap_5G;

pthread_mutex_t g_mutex;
sem_t g_semaphore;
time_t g_current_time;

static int quick_select(int* arr, int len, int k)
{
    int pivot, i, j, tmp;

    pivot = arr[len / 2];

    for (i = 0, j = len - 1;; i++, j--) {
        while (arr[i] < pivot) i++;
        while (arr[j] > pivot) j--;
        if (i >= j) break;
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

int get_channel_info(struct channel_info *info,int band) 
{
    FILE *fp;
    char *rbuf;
    char *p;
    char cmd[1024];

    if (info == NULL) {
         return FAIL;
    }

    if (band == 5) {
#ifdef BRIDGE_PLATFORM
        execute_cmd("wlanconfig ra0 radio",&rbuf);
#elif defined AP
        execute_cmd("wlanconfig rax0 radio",&rbuf);
#endif
    } else if (band == 2) {

    } else {
        return FAIL;
    }
    
    
    strtok(rbuf,"\n");

    strtok(NULL,":");
    p = strtok(NULL,"\n");


    info->channel=atoi(p);
      
    strtok(NULL,":");
    p = strtok(NULL,"\n");
    info->floornoise=atoi(p);
     
    strtok(NULL,":");
    p = strtok(NULL,"\n");
    info->utilization=atoi(p);
     
    strtok(NULL,"\n");
    strtok(NULL,":");
    p = strtok(NULL,"\n");
    info->bw = atoi(p);
    
    strtok(NULL,":");
    p = strtok(NULL,"\n");
    info->obss_util=atoi(p);
    
    strtok(NULL,":");
    p = strtok(NULL,"\n");
    info->tx_util=atoi(p);
   
    strtok(NULL,":");
    p = strtok(NULL,"\n");

    info->rx_util=atoi(p);
    
    free(rbuf);

    return SUCCESS;
}

void channel_scan(struct channel_info *input,int scan_time) 
{
    FILE *fp;
    int i;
    struct channel_info info[MAX_SCAN_TIME];
    int utilization_temp[MAX_SCAN_TIME];
    int obss_util_temp[MAX_SCAN_TIME];
    int floornoise_temp[MAX_SCAN_TIME];
    
    if (scan_time > MAX_SCAN_TIME) {
        scan_time = MAX_SCAN_TIME;
    } 

    if (scan_time < MIN_SCAN_TIME) {
        scan_time = MIN_SCAN_TIME;
    }     

    for (i = 0 ;i < scan_time ;i++) {
        sleep(1);
        get_channel_info(&info[i],PLATFORM_5G);
    }
    fp = fopen("./channel_info","a+");
    fprintf(fp,"\r\n********channel %d ***********\r\n",info[0].channel);
    fprintf(fp,"bw %d\r\n",input->bw=info[0].bw);
    fprintf(fp,"floornoise\t");
    fprintf(fp,"utilization\t");
    fprintf(fp,"obss_util\t");
    fprintf(fp,"rx_util\t\t");
    fprintf(fp,"tx_util\r\n");

    for (i = 0 ;i < scan_time ;i++) {
        fprintf(fp,"%d\t\t",floornoise_temp[i] = info[i].floornoise);
        fprintf(fp,"%d\t\t",utilization_temp[i] = info[i].utilization);
        fprintf(fp,"%d\t\t",obss_util_temp[i] = info[i].obss_util);
        fprintf(fp,"%d\t\t",info[i].rx_util);
        fprintf(fp,"%d\r\n",info[i].tx_util);
    }

    printf("median floornoise%d \r\n",input->floornoise = median(floornoise_temp,scan_time));
    printf("median utilization%d \r\n",input->utilization = median(utilization_temp,scan_time));
    printf("median obss_util%d \r\n",input->obss_util = median(obss_util_temp,scan_time));
    
    fprintf(fp,"*******************************************************\r\n");
    fclose(fp);
    printf("g_status %d \r\n",g_status);

}
    
void *scan_func() 
{

    char *json_str;

    
    int i,j,len;
    double score;
    struct channel_info current_channel_info;
    
    
    while (1) {
        sem_wait(&g_semaphore);
        
        if (g_status == SCAN_BUSY) {
            get_channel_info(&current_channel_info,PLATFORM_5G);
            memset(realtime_channel_info_5g,0,sizeof(realtime_channel_info_5g));
            for (j = 0,i = 0; i < sizeof(long) * ONE_BYTE; i++) {
                if ((g_input.channel_bitmap& (1L << i)) != 0) {
                    
                    realtime_channel_info_5g[j].channel = bitmap_to_channel(i);
                    printf("change to channel %d >>>>>\n",realtime_channel_info_5g[j].channel);
                    
                    change_channel(realtime_channel_info_5g[j].channel);

                    channel_scan(&realtime_channel_info_5g[j],g_input.scan_time);
                    sleep(1);
                    printf("%ld\r\n",g_input.channel_bitmap);
                    realtime_channel_info_5g[j].score = calculate_channel_score(&realtime_channel_info_5g[j]);
                    printf("------------------\r\n");
                    j++;  
                }

                if (g_status == SCAN_TIMEOUT) {
                    goto timeout;
                }
            }
            
            /* timestamp */
            g_current_time = time(NULL);
            change_channel(current_channel_info.channel);

            
            pthread_mutex_lock(&g_mutex);
            
            memcpy(g_channel_info_5g,realtime_channel_info_5g,sizeof(realtime_channel_info_5g));
            memset(realtime_channel_info_5g,0,sizeof(realtime_channel_info_5g));
            g_status = SCAN_IDLE;
            g_input.scan_time = MIN_SCAN_TIME; /* restore scan time */
            pthread_mutex_unlock(&g_mutex);
        }
timeout:
    if (g_status == SCAN_TIMEOUT) {
            change_channel(current_channel_info.channel);
            pthread_mutex_lock(&g_mutex);
            g_status = SCAN_IDLE;
            g_input.scan_time = MIN_SCAN_TIME; /* restore scan time */
            memset(realtime_channel_info_5g,0,sizeof(realtime_channel_info_5g));
            pthread_mutex_unlock(&g_mutex);
        }
    }
}

double calculate_channel_score(struct channel_info *info) 
{
    double N;

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
    return ((double)1 - N/20)*(double)(100 - info->obss_util)/100;
}



#ifdef POPEN_CMD_ENABLE
int change_channel(int channel) 
{
    char cmd[MAX_POPEN_BUFFER_SIZE];
    printf("change to channel %d",channel);
    sprintf(cmd,"dev_config update -m radio '{ \"radioList\": [ { \"radioIndex\": \"1\", \"type\":\"5G\", \"channel\":\"%d\" } ]}'",channel);
    // sprintf(cmd,"iwpriv ra0 set channel=%d",channel);
    execute_cmd(cmd,NULL);

    return 0;
}
#elif defined UNIFY_FRAMEWORK_ENABLE
int change_channel(int channel) 
{
    uf_cmd_msg_t *msg_obj;
    int ret;
    char* rbuf;
    char param[100];
    
    sprintf(param,"{\"radioList\": [ { \"radioIndex\": \"1\", \"type\":\"5G\", \"channel\":\"%d\" }]}",channel);
    printf("%s\r\n",param);
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
    // printf("%s\r\n",rbuf);
    if (rbuf) {
      free(rbuf);
    }
    free(msg_obj);
}
#endif



