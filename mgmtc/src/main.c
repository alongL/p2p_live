#include "iotc.h"
#include <pthread.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <netinet/tcp.h>


/** global data **/
char iotc_server_ip[MAX_IP_LEN]="115.29.49.52";
char iotc_wan_ip[MAX_IP_LEN];
char iotc_stun_ip[MAX_IP_LEN];
char iotc_upnp_extern_ip[MAX_IP_LEN];
int iotc_server_port=80;
bool isPublicIp = false;

unsigned long long  rxBytesStart;
unsigned long long  rxBytesEnd;
unsigned long long  txBytesStart;
unsigned long long  txBytesEnd;
SpeedTestType speedTestEnable;

int iotc_Tm1();
int iotc_Tm2();
int iotc_Tm3();
int iotc_Tm4();
int iotc_SpeedTest();

struct uloop_timeout g_timeoutTm1 = {
    .cb = iotc_Tm1,
};
struct uloop_timeout g_timeoutTm2 = {
    .cb = iotc_Tm2,
};
struct uloop_timeout g_timeoutTm3 = {
    .cb = iotc_Tm3,
};
struct uloop_timeout g_timeoutTm4 = {
    .cb = iotc_Tm4,
};

struct uloop_timeout g_timeoutSpeedTest = {
    .cb = iotc_SpeedTest,
};


extern int connection_init(void);
extern void *ipc_process_task_thread(void *arg);
extern void *speed_test_process_task_thread(void *arg);
extern void *check_available_process_task_thread(int arg);
void printids(const char *s);

void printids(const char *s)
{
    pid_t pid;
    pthread_t tid;

    pid = getpid();
    tid = pthread_self();

    iotc_debug("%s[%d]: %s pid %u tid %u (0x%x)\n", __func__, __LINE__, 
        s, (unsigned int) pid, (unsigned int) tid, (unsigned int) tid);
}

int iotc_Tm1()
{

    iotc_debug("Enter.");

    FILE *fp;
    char cmdline[128];
    char *ptr,*ptrIpStart;
    char line[128],bytes[16];

    memset(line,0,sizeof(line));
    memset(bytes,0,sizeof(bytes));

    system("ifconfig eth0.2 > /var/speedtest");
    if((fp=fopen("/var/speedtest","r"))==NULL){
        printf("fopen error\n");
        return NULL;
    }
    memset(line, 0, sizeof(line));
    while(fgets(line,sizeof(line),fp))
    {
        ptr = strstr(line, "RX bytes");
        if (!ptr){
            continue;
        }
        while(*ptr++ != ':')
            ;

        ptrIpStart = ptr;
        while(*ptr != ' ') {
            ptr++;
        }
        *ptr = '\0';
        strcpy(bytes, ptrIpStart);
        iotc_debug("bytes:%s",bytes);
        rxBytesStart = strtoull(bytes, NULL, 0);
        iotc_debug("rxBytesStart:%llu",rxBytesStart);

        break;
    }
    fclose(fp);
    iotc_debug("Exit.");

    return 0;
}

int iotc_Tm2()
{

    iotc_debug("Enter.");

    FILE *fp;
    char cmdline[128];
    char *ptr,*ptrIpStart;
    char line[128],bytes[16];

    memset(line,0,sizeof(line));
    memset(bytes,0,sizeof(bytes));

    system("ifconfig eth0.2 > /var/speedtest");
    if((fp=fopen("/var/speedtest","r"))==NULL){
        printf("fopen error\n");
        return NULL;
    }
    memset(line, 0, sizeof(line));
    while(fgets(line,sizeof(line),fp))
    {
        ptr = strstr(line, "RX bytes");
        if (!ptr){
            continue;
        }
        while(*ptr++ != ':')
            ;

        ptrIpStart = ptr;
        while(*ptr != ' ') {
            ptr++;
        }
        *ptr = '\0';
        strcpy(bytes, ptrIpStart);
        iotc_debug("bytes:%s",bytes);
        rxBytesEnd = strtoull(bytes, NULL, 0);
        iotc_debug("rxBytesEnd:%llu",rxBytesEnd);

        break;
    }
    fclose(fp);
    iotc_debug("Exit.");
    speedTestEnable = SPEED_TEST_STOP;

    return 0;
}

int iotc_Tm3()
{

    iotc_debug("Enter.");

    FILE *fp;
    char cmdline[128];
    char *ptr,*ptrIpStart;
    char line[128],bytes[16];

    memset(line,0,sizeof(line));
    memset(bytes,0,sizeof(bytes));

    system("ifconfig eth0.2 > /var/speedtest");
    if((fp=fopen("/var/speedtest","r"))==NULL){
        printf("fopen error\n");
        return NULL;
    }
    memset(line, 0, sizeof(line));
    while(fgets(line,sizeof(line),fp))
    {
        ptr = strstr(line, "TX bytes");
        if (!ptr){
            continue;
        }
        while(*ptr++ != ':')
            ;

        ptrIpStart = ptr;
        while(*ptr != ' ') {
            ptr++;
        }
        *ptr = '\0';
        strcpy(bytes, ptrIpStart);
        iotc_debug("bytes:%s",bytes);
        txBytesStart = strtoull(bytes, NULL, 0);
        iotc_debug("txBytesStart:%llu",txBytesStart);

        break;
    }
    fclose(fp);
    iotc_debug("Exit.");

    return 0;
}

int iotc_Tm4()
{

    iotc_debug("Enter.");

    FILE *fp;
    char cmdline[128];
    char *ptr,*ptrIpStart;
    char line[128],bytes[16];

    memset(line,0,sizeof(line));
    memset(bytes,0,sizeof(bytes));

    system("ifconfig eth0.2 > /var/speedtest");
    if((fp=fopen("/var/speedtest","r"))==NULL){
        printf("fopen error\n");
        return NULL;
    }
    memset(line, 0, sizeof(line));
    while(fgets(line,sizeof(line),fp))
    {
        ptr = strstr(line, "TX bytes");
        if (!ptr){
            continue;
        }
        while(*ptr++ != ':')
            ;

        ptrIpStart = ptr;
        while(*ptr != ' ') {
            ptr++;
        }
        *ptr = '\0';
        strcpy(bytes, ptrIpStart);
        iotc_debug("bytes:%s",bytes);
        txBytesEnd = strtoull(bytes, NULL, 0);
        iotc_debug("txBytesEnd:%llu",txBytesEnd);

        break;
    }
    fclose(fp);
    iotc_debug("Exit.");
    speedTestEnable = SPEED_TEST_STOP;

    return 0;
}

int iotc_SpeedTest()
{
    int len = 0;
    int testfd = -1;
    char buf[RECV_MAX_BUF_LEN] = {0};
    struct sockaddr_in test_addr;

    if ((testfd = socket(AF_INET,SOCK_STREAM,0)) < 0)
    {
        iotc_error("failed to socket! %s", strerror(errno));
        return -1;
    }
    iotc_debug("socket create succeed, speed test fd=%d", testfd);


    memset(&test_addr,0,sizeof(test_addr));
    test_addr.sin_family      = AF_INET;
    test_addr.sin_addr.s_addr = inet_addr(iotc_server_ip);
    test_addr.sin_port        = htons(9124);

    while (1)
    {
        if (connect(testfd, (struct sockaddr *)&test_addr, sizeof(test_addr)) == 0)
        {
            iotc_debug("connect to speed test server succeed.");
            break;
        }

        sleep(2);

        iotc_debug("trying to connect to speed test server...");
    }

    iotc_debug("Start speed test.");

    uloop_timeout_set(&g_timeoutTm1, 5000);
    uloop_timeout_set(&g_timeoutTm2, 15000);
    uloop_timeout_set(&g_timeoutTm3, 20000);
    uloop_timeout_set(&g_timeoutTm4, 30000);

    speedTestEnable = SPEED_TEST_START;
    while(speedTestEnable){
     iotc_debug("Start speed test.");
       len=recv(testfd, buf, RECV_MAX_BUF_LEN, 0);
    iotc_debug("Start speed test.");
        if ((len <= 0))
        {
            iotc_error("recv from fd(%d) error: %s, len = %d", testfd, strerror(errno), len);
        }
    }

    speedTestEnable = SPEED_TEST_START;
    while(speedTestEnable){
    iotc_debug("Start speed test.");
        len=send(testfd, buf, RECV_MAX_BUF_LEN, 0);
     iotc_debug("Start speed test.");
       if ((len <= 0))
        {
            iotc_error("recv from fd(%d) error: %s, len = %d", testfd, strerror(errno), len);
        }
    }
    close(testfd);
    iotc_debug("Start speed test.");

    iotc_sendDevBwInfoMsg();
    
    return 0;
}


static int config_init(int argc, char *argv[])
{
    int i=0;
    char tmpStr[32]={0};
    char *tmpServerIp=NULL;
    char *tmpServerPort=NULL;
    char serverStr[128]={0};

    iotc_debug("Enter.");

    for(i = 0; i < argc; i ++)
    {
        if(1 == i)
        {
            strncpy(tmpStr, argv[i], sizeof(tmpStr) - 1 );
            tmpServerIp = strtok(tmpStr,":");
            tmpServerPort = strtok(NULL, ":");

            if((NULL != tmpServerIp) && (NULL != tmpServerPort))
            {
                memset(iotc_server_ip, 0, MAX_IP_LEN);
                strncpy(iotc_server_ip, tmpServerIp, MAX_IP_LEN - 1);
                iotc_server_port = atoi(tmpServerPort);
            }

            break;
        }
    }

    snprintf(serverStr, 128, "%s:%d", iotc_server_ip, iotc_server_port);
    serverStr[127]='\0';
    iotc_debug("server=%s", serverStr);
    iotc_genHostStr(serverStr);

    iotc_debug("Exit.");

    return 0;
}

void stun_detect_init()
{
    FILE *fp;
    char cmdline[128];
    char *ptr,*ptrIpStart;
    char line[128],wanip[16];

    memset(line,0,sizeof(line));
    memset(wanip,0,sizeof(wanip));

    system("iptables -F zone_wan_src_REJECT");

    while(strlen(wanip) == 0) {
        system("ifconfig eth0.2 > /var/wanipinfo");
        if((fp=fopen("/var/wanipinfo","r"))==NULL){
            printf("fopen error\n");
            return NULL;
        }
        memset(line, 0, sizeof(line));
        while(fgets(line,sizeof(line),fp))
        {
            ptr = strstr(line, "inet addr");
            if (!ptr){
                //printf("ptr is NULL!\n");
                continue;
            }
            while(*ptr++ != ':')
                ;

            ptrIpStart = ptr;
            while(*ptr != ' ') {
                ptr++;
            }
            *ptr = '\0';
            strcpy(wanip, ptrIpStart);
            strcpy(iotc_wan_ip, ptrIpStart);
            printf("wanip:%s\n",wanip);
            break;
        }
        fclose(fp);
        sleep(2);
    }

    iotc_debug("stun_detect_init iotc_server_ip:%s\r\n","172.17.72.249");
    sprintf(cmdline, "stun-client %s 1 > /var/stun_info", "172.17.72.249");
    system(cmdline);
    if((fp=fopen("/var/stun_info","r"))==NULL){
        printf("fopen error\n");
        return NULL;
    }
    while(fgets(line,sizeof(line),fp))
    {
        ptr = strstr(line, "mappedAddr");
        if (!ptr){
            //printf("ptr is NULL!\n");
            continue;
        }
        while(*ptr++ != '=')
            ;

        ptrIpStart = ptr;
        while(*ptr != ':') {
            ptr++;
        }
        *ptr = '\0';
        strcpy(iotc_stun_ip, ptrIpStart);
        printf("stunip:%s\n",iotc_stun_ip);
        break;
    }
    fclose(fp);
    
    if(!strcmp(wanip,iotc_stun_ip))
        isPublicIp = true;
}

void upnpc_init(int port)
{
    FILE *fp;
    char cmdline[128];
    char *ptr,*ptrIpStart;
    char line[128];

    system("iptables -F zone_wan_src_REJECT");
    
    sprintf(cmdline, "upnpc -a %s %d %d UDP > /var/upnpinfo",iotc_wan_ip,port,port);
    system(cmdline);
    iotc_debug(" %s\r\n",cmdline);
    if((fp=fopen("/var/upnpinfo","r"))==NULL){
        printf("fopen error\n");
        return NULL;
    }
    while(fgets(line,sizeof(line),fp))
    {
        ptr = strstr(line, "external");
        if (!ptr){
            continue;
        }
        while(*ptr++ != ' ')
            ;

        ptrIpStart = ptr;
        while(*ptr != ':') {
            ptr++;
        }
        *ptr = '\0';
        strcpy(iotc_upnp_extern_ip, ptrIpStart);
        printf("upnp external ip:%s\n",iotc_upnp_extern_ip);
        break;
    }
    fclose(fp);
}

void externalDetectAvailable()
{
    return;
}

void checkExternalAvailable(int port)
{
    int ret = -1;
    pthread_t tid;

    ret = pthread_create(&tid,NULL,check_available_process_task_thread, port);
    iotc_debug(" ret = %d\n", ret);
    if(ret != 0)
    {
        perror("can't create thread: %s\n");
    }
}

struct uloop_timeout g_sendDevOnlineTm = {
    .cb = iotc_sendDevOnlineMsg,
};

int main(int argc, char *argv[])
{
    pthread_t tid;
    int ret = -1;
/*
    struct uloop_timeout g_timeoutTm1 = {
        .cb = iotc_Tm1,
    };
    struct uloop_timeout g_timeoutTm2 = {
        .cb = iotc_Tm2,
    };
    struct uloop_timeout g_timeoutTm3 = {
        .cb = iotc_Tm3,
    };
    struct uloop_timeout g_timeoutTm4 = {
        .cb = iotc_Tm4,
    };
*/

    config_init(argc, argv);
    stun_detect_init();

    if(isPublicIp)
    {
        externalDetectAvailable();
    } else {
        upnpc_init(10008);
        checkExternalAvailable(10008);
    }

    if (glue_init() != 0)
    {
        iotc_error("glue init failed!");
        return -1;
    }

    if (0 != connection_init())
    {
        iotc_error("socket_init failed!");
        return -1;
    }

    ret = pthread_create(&tid, NULL, ipc_process_task_thread, NULL);
    iotc_debug("%s[%d]: ret = %d\n", __func__, __LINE__, ret);
    if(ret != 0)
    {
        perror("can't create thread: %s\n");
    }

    uloop_init();
#ifdef HTTP_SERVER
    uloop_fd_add(&iotc_monitor_http_uloop_fd, ULOOP_READ);
#endif
    uloop_fd_add(&iotc_monitor_manage_uloop_fd, ULOOP_READ);
    uloop_timeout_set(&g_sendDevOnlineTm, 2000);

    ret = pthread_create(&tid, NULL, speed_test_process_task_thread, NULL);
    iotc_debug("%s[%d]: ret = %d\n", __func__, __LINE__, ret);
    if(ret != 0)
    {
        perror("can't create thread: %s\n");
    }

    //uloop_timeout_set(&g_timeoutSpeedTest, 5000);
/*
    uloop_timeout_set(&g_timeoutTm1, 5000);
    uloop_timeout_set(&g_timeoutTm2, 15000);
    uloop_timeout_set(&g_timeoutTm3, 20000);
    uloop_timeout_set(&g_timeoutTm4, 30000);
*/
    uloop_run();
    uloop_done();

    return 0;
}
