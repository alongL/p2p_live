#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include "log.h"
#include "heap.h"
#include "sock.h"
#include "socks.h"
#include "http.h"

#define BUFFER_SIZE 1024
#if 0
#define HTTP_POST "POST /%s HTTP/1.1\r\nHOST: %s:%d\r\nAccept: */*\r\n"\
    "Content-Type:application/x-www-form-urlencoded\r\nContent-Length: %d\r\n\r\n%s"
#endif

#define HTTP_POST "POST /%s HTTP/1.1\r\nHost: %s:%d\r\nAccept: */*\r\n"\
    "Content-Type:application/json;charset=UTF-8\r\nContent-Length: %d\r\n\r\n%s"
#define HTTP_GET "GET %s HTTP/1.1\r\nHost: %s:%d\r\nAccept: */*\r\n\r\n"

#define MSG_GET_RESOURCE    0
#define MSG_NEW_RESOUCE     1
#define MSG_RESOUCE_DOWN    2
#define MSG_NEW_CONN        3
#define MSG_CONN_DOWN       4

#define DEV_ID_LEN 128
#define ZB_SRV_URL_LEN 128
#define RESID_LEN  64
#define SERVICE_URL_LEN 256

#define MAX_HOST_LEN 256
#define MAX_PATH_LEN 32

#define DEV_ID_FILE "/var/deviceid"
#define ZB_SRV_URL_FILE "/var/zburl"

char g_srv_url[ZB_SRV_URL_LEN] = {'H', 'H', 'H', 'H', '\0'};
char g_devId[DEV_ID_LEN] = {'H', 'H', 'H', 'H', '\0'};
char g_resId[RESID_LEN]={0};
char g_src[DEV_ID_LEN] = {0};

struct res_s {
    char devId[DEV_ID_LEN];
    char url[SERVICE_URL_LEN];
    int metric;
    struct res_s *next;
};

struct res_s *res_list=NULL;

void add_resource(const char *devId, const char *url)
{
    struct res_s *newres;

    if (strlen(devId) >= DEV_ID_LEN) {
        return;
    }
    if (strlen(url) >= SERVICE_URL_LEN) {
        return;
    }

    newres = (struct res_s *) safemalloc (sizeof (struct res_s));
    if (!newres) {
        return;
    }
    strcpy(newres->devId, devId);
    strcpy(newres->url, url);
    
    newres->next = res_list;
    res_list = newres;
}

void clear_resource_list(void)
{
    struct res_s *res=res_list;
    struct res_s *res_next;

    res_list = NULL;
    while(res) {
        res_next = res->next;
        safefree(res);
        res = res_next;
    }
}

static char *get_device_id()
{
    int fd,size;
    char buf[256]={0};
#if 0
    unsigned char macaddr[6];
    int sk=-1;
    struct ifreq req;
    int err;
#endif

    if (strncmp(g_devId, "HHHH", 4)) {
        return g_devId;
    }

    if ((fd=open(DEV_ID_FILE, O_RDONLY)) < 0) {
        log_message (LOG_ERR, "open %s failed!:%s", DEV_ID_FILE, strerror(errno));
        return -1;
    }

    size = read(fd, buf, 255);
    close(fd);
    if (size < 0 || size >= DEV_ID_LEN) {
        log_message (LOG_ERR, "read %s return %d, error.:%s", DEV_ID_FILE, size, strerror(errno));
        return -1;
    }

    if (buf[size-1] == '\n') {
        buf[size-1] = '\0';
    }
    strcpy(g_devId, buf);

#if 0
#define TEST_DEV_ID "20170612"
    sk = socket(AF_INET,SOCK_DGRAM,0);
    strcpy(req.ifr_name, "eth0.2");
    err = ioctl(sk, SIOCGIFHWADDR, &req);
    close(sk);
    if (err!= -1) {
        memcpy(macaddr, req.ifr_hwaddr.sa_data, 6);
        sprintf(g_devId, "%s%d%d%d", TEST_DEV_ID, macaddr[3], macaddr[4], macaddr[5]);
    } else {
        strcpy(g_devId, TEST_DEV_ID);
    }
#endif
    return g_devId;
}

static char *get_zb_srv_url()
{
    int fd,size;
    char buf[256]={0};

    if (strncmp(g_srv_url, "HHHH", 4)) {
        return g_srv_url;
    }

    if ((fd=open(ZB_SRV_URL_FILE, O_RDONLY)) < 0) {
        log_message (LOG_ERR, "open %s failed!", ZB_SRV_URL_FILE);
        return g_srv_url;
    }

    size = read(fd, buf, 255);
    close(fd);
    if (size < 0 || size >= ZB_SRV_URL_LEN) {
        log_message (LOG_ERR, "read %s return %d, error.", ZB_SRV_URL_FILE, size);
        return g_srv_url;
    }

    if (buf[size-1] == '\n') {
        buf[size-1] = '\0';
    }
    strcpy(g_srv_url, buf);

    return g_srv_url;
}

int init_in_parent_process(void)
{
    system("mkdir -p /var/ptpc");
    system("echo 0 > /var/ptpc/downloadmode");
    system("insmod /lib/modules/3.10.14/zb_redirect.ko &");
    get_device_id();
    get_zb_srv_url();
    return 0;
}


void build_srv_url(char *url, int port, char *resId)
{
    int sockfd;
    char ip[16];
    struct ifreq req;
    struct sockaddr_in *host;
     
    if (-1 == (sockfd = socket(PF_INET, SOCK_STREAM, 0)))
    {
        perror( "socket" );
        return -1;
    }
     
    bzero(&req, sizeof(struct ifreq));
    strcpy(req.ifr_name, "eth0.2");
    ioctl(sockfd, SIOCGIFADDR, &req);
    host = (struct sockaddr_in*)&req.ifr_addr;
    strcpy(ip, inet_ntoa(host->sin_addr));
    close(sockfd);

    sprintf(url, "http://%s:%d/%s", ip, port, resId);
}

int check_resId(char *resId)
{
    int len=0;

    len = strlen(resId);
    if (len == 0 || len > RESID_LEN) {
        return -1;
    }
    return 0;
}

int parse_url(const char *url, char *host, int *port, char *path)
{
    char port_str[16]={0};
    char *ptr=NULL;
    int len=0;

    if (!url) {
        return -1;
    }

    if (strncmp(url, "http://", 7)) {
        log_message (LOG_ERR, "invalid url %s ", url);
        return -1;
    }

    if ((ptr=strchr(url+7, '/')) != NULL) {
        if (strlen(ptr) >= MAX_PATH_LEN) {
            return -1;
        }
        strcpy(path, ptr);

        len = ptr-url-7;
        if (len >= MAX_HOST_LEN) {
            return -1;
        }
        strncpy(host, url+7, len);
        *(host+len) = '\0';
    } else {
        strcpy(path, "/");
        if (strlen(url+7) >= MAX_HOST_LEN) {
            return -1;
        }
        strcpy(host, url+7);
    }

    if ((ptr=strchr(host, ':')) == NULL) {
        *port = 80;
    } else {
        *ptr='\0';
        *port = atoi(ptr+1);

        if (*port <= 0) {
            return -1;
        }
    }

    log_message (LOG_INFO, "host:%s port:%d", host, *port);
    return 0;
}

static int http_tcpclient_create(const char *host, int port)
{
    int socket_fd;
#if 0
    struct hostent *he;
    struct sockaddr_in server_addr;

    if((he = gethostbyname(host))==NULL) {
        return -1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr = *((struct in_addr *)he->h_addr);

    if((socket_fd = socket(AF_INET,SOCK_STREAM,0))==-1){
        return -1;
    }

    if(connect(socket_fd, (struct sockaddr *)&server_addr,sizeof(struct sockaddr)) == -1){
        return -1;
    }
#endif

    socket_fd = opensock (host, port, NULL);
    if (socket_fd > 0) {
        log_message (LOG_INFO, "connected to %s:%d fd=%d ", host, port, socket_fd);
    } else {
        log_message (LOG_ERR, "connect to %s:%d failed!", host, port);
        close(socket_fd);
    }

    return socket_fd;
}

static void http_tcpclient_close(int socket)
{
    close(socket);
}

static int http_parse_url(const char *url,char *host,char *file,int *port)
{
    char *ptr1,*ptr2;
    int len = 0;
    if(!url || !host || !file || !port){
        return -1;
    }

    ptr1 = (char *)url;

    if(!strncmp(ptr1,"http://",strlen("http://"))){
        ptr1 += strlen("http://");
    }else{
        return -1;
    }

    ptr2 = strchr(ptr1,'/');
    if(ptr2){
        len = strlen(ptr1) - strlen(ptr2);
        memcpy(host,ptr1,len);
        host[len] = '\0';
        if(*(ptr2 + 1)){
            memcpy(file,ptr2 + 1,strlen(ptr2) - 1 );
            file[strlen(ptr2) - 1] = '\0';
        }
    }else{
        memcpy(host,ptr1,strlen(ptr1));
        host[strlen(ptr1)] = '\0';
    }
    /*get host and ip*/
    ptr1 = strchr(host,':');
    if(ptr1){
        *ptr1++ = '\0';
        *port = atoi(ptr1);
    }else{
        *port = MY_HTTP_DEFAULT_PORT;
    }

    return 0;
}


static int http_tcpclient_recv(int fd, char *lpbuff)
{
    int recvnum=0;
    char *l_ptr=NULL, *ptr=NULL;
    char contlenstr[16]={0};
    int len=0, cont_len=-1, head_len=-1, tot_len=-1;

    len = recv(fd, lpbuff, BUFFER_SIZE*4, 0);
    if (len < 0) {
        log_message (LOG_INFO, "%s %d: recv resp error %s", __FUNCTION__, __LINE__, strerror(errno));
        return len;
    }
    recvnum += len;
    lpbuff[recvnum] = 0;
    
    ptr = (char*)strstr(lpbuff,"\r\n\r\n");
    if (!ptr) {
        log_message (LOG_INFO, "%s %d: not found end of http head", __FUNCTION__, __LINE__);
        return 0;
    }

    head_len = ptr - lpbuff + 4;

    l_ptr = strstr(lpbuff, "Content-Length:");
    if (!l_ptr) {
        log_message (LOG_INFO, "%s %d: not found Content-Length", __FUNCTION__, __LINE__);
        return 0;
    }

    ptr = l_ptr + strlen("Content-Length:");
    while(*ptr == ' ') {
        ptr++;
    }
    l_ptr = ptr;

    while(*ptr) {
        if(*ptr == '\r') {
            if (ptr-l_ptr > 15) {
                log_message (LOG_INFO, "%s %d: Content-Length parse error!", __FUNCTION__, __LINE__, ptr-l_ptr);
                return -1;
            }
            memcpy(contlenstr, l_ptr, ptr-l_ptr);
            contlenstr[ptr-l_ptr] = '\0';
            cont_len = atoi(contlenstr);
            break;
        }
        ptr++;
    }

    if (cont_len < 0) {
        log_message (LOG_INFO, "%s %d: content length %d is error!", __FUNCTION__, __LINE__, cont_len);
        return 0;
    }

    tot_len = head_len + cont_len;
    while(recvnum < tot_len) {
        len = recv(fd, lpbuff+recvnum, BUFFER_SIZE*4-(tot_len-recvnum), 0);
        if(len < 0) {
            log_message (LOG_INFO, "%s %d: %s lpbuff=%s", __FUNCTION__, __LINE__, strerror(errno), lpbuff);
            return 0;
        }
        recvnum += len;
    }

    lpbuff[recvnum] = 0;
    return recvnum;
}

static int http_tcpclient_send(int socket,char *buff,int size)
{
    int sent=0, tmpres=0;

    while(sent < size) {
        tmpres = send(socket, buff+sent, size-sent, 0);
        if (tmpres == -1) {
            return -1;
        }
        sent += tmpres;
    }
    return sent;
}

static char *http_parse_result(const char *lpbuf)
{
    char *ptmp = NULL;
    char *response = NULL;

    ptmp = (char*)strstr(lpbuf,"HTTP/1.1");
    if (!ptmp) {
        log_message(LOG_ERR, "http/1.1 not faind\n");
        return NULL;
    }

    if (atoi(ptmp + 9)!=200) {
        log_message(LOG_ERR, "result:\n%s\n",lpbuf);
        return NULL;
    }

    ptmp = (char*)strstr(lpbuf,"\r\n\r\n");
    if (!ptmp) {
        log_message(LOG_ERR, "ptmp is NULL\n");
        return NULL;
    }
    response = (char *)malloc(strlen(ptmp)+1);
    if (!response) {
        log_message(LOG_ERR, "malloc failed \n");
        return NULL;
    }
    strcpy(response,ptmp+4);
    return response;
}

char* http_post(const char *url, const char *post_str)
{
    char lpbuf[BUFFER_SIZE*4]={0};
    char host_addr[BUFFER_SIZE]={0};
    char file[BUFFER_SIZE]={0};
    int fd=-1;
    int port=0;
    struct timeval tv;

    tv.tv_sec = 0;
    tv.tv_usec = 500000;


    if (!url || !post_str) {
        log_message(LOG_ERR, "failed!\n");
        return NULL;
    }

    if (http_parse_url(url, host_addr, file, &port)) {
        log_message(LOG_ERR, "http_parse_url failed!\n");
        return NULL;
    }

    fd = http_tcpclient_create(host_addr, port);
    if (fd < 0){
        log_message(LOG_ERR, "http_tcpclient_create failed\n");
        return NULL;
    }

    sprintf(lpbuf, HTTP_POST, file, host_addr, port, strlen(post_str), post_str);

    if (http_tcpclient_send(fd, lpbuf, strlen(lpbuf)) < 0) {
        log_message(LOG_ERR, "http_tcpclient_send failed..\n");
        return NULL;
    }

    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(struct timeval));

    /*it's time to recv from server*/
    memset(lpbuf, 0, sizeof(lpbuf));
    if (http_tcpclient_recv(fd, lpbuf) <= 0) {
        log_message(LOG_ERR, "http_tcpclient_recv failed\n");
        return NULL;
    }

    http_tcpclient_close(fd);

    return http_parse_result(lpbuf);
}

char *http_get(const char *url)
{
    int socket_fd = -1;
    char lpbuf[BUFFER_SIZE*4] = {0};
    char host_addr[BUFFER_SIZE] = {0};
    char file[BUFFER_SIZE] = {0};
    int port = 0;

    if (!url) {
        log_message(LOG_ERR, "failed!\n");
        return NULL;
    }

    if (http_parse_url(url, host_addr, file, &port)) {
        log_message(LOG_ERR, "http_parse_url failed!\n");
        return NULL;
    }

    socket_fd =http_tcpclient_create(host_addr, port);
    if (socket_fd < 0) {
        log_message(LOG_ERR, "http_tcpclient_create failed\n");
        return NULL;
    }

    sprintf(lpbuf, HTTP_GET, file, host_addr, port);

    if (http_tcpclient_send(socket_fd,lpbuf,strlen(lpbuf)) < 0) {
        log_message(LOG_ERR, "http_tcpclient_send failed..\n");
        return NULL;
    }

    memset(lpbuf, 0, sizeof(lpbuf));
    if (http_tcpclient_recv(socket_fd, lpbuf) <= 0) {
        log_message(LOG_ERR, "http_tcpclient_recv failed\n");
        return NULL;
    }
    http_tcpclient_close(socket_fd);

    return http_parse_result(lpbuf);
}

/* parse the response, and add ro res_list */
int parse_resource_list(char *string)
{
    int cnt=0;
    char *ptr=NULL, *ptr2=NULL, *id_ptr=NULL, *url_ptr=NULL;
    char *resId_s=NULL, *resId_e=NULL;
    int get_start=0;
    int len=0;
    /*{"type":0,"ret":0,"resId":2,"list":[{"deviceId":"201706120001","url":"http://10.6.61.146:9999/2"}]}*/

    ptr = strstr(string, "\"resId\":");
    if (!ptr) {
        return cnt;
    }

    ptr2 = ptr + 8;
    while(*ptr2) {
        if (*ptr2 == ',' || *ptr2 == '}') {
            resId_e = ptr2;
            break;
        } else if (*ptr2 != ' ') {
            if (get_start==0) {
                resId_s = ptr2;
                get_start = 1;
            }
        }
        ptr2++;
    }
    len = resId_e - resId_s;
    if (len < RESID_LEN) {
        memcpy(g_resId, resId_s, len);
        g_resId[len] = 0;
    } else {
        log_message(LOG_ERR, "resId len %d is larger than 64!", len);
        return cnt;
    }
    log_message(LOG_ERR, "resId=%s", g_resId);

    /*{"type":0,"ret":0,"resId":2,"list":[{"deviceId":"201706120001","url":"http://10.6.61.146:9999/2"}]}*/

    ptr = strstr(string, "\"list\":");
    if (!ptr) {
        return cnt;
    }

    ptr += 7;
    while(*ptr) {
        id_ptr = strstr(ptr, "\"deviceId\":");
        if (!id_ptr) {
            break;
        }
        ptr2 = id_ptr + 11;
        get_start = 0;
        while(*ptr2) {
            if(*ptr2 == '\"') {
                if (get_start) {
                    *ptr2 = '\0';
                    break;
                } else {
                    get_start=1;
                    id_ptr = ptr2+1;
                }
            }
            ptr2++;
        }

        ptr = ptr2+1;
        url_ptr = strstr(ptr, "\"url\":");
        if (!url_ptr) {
            break;
        }

        ptr2 = url_ptr + 6;
        get_start = 0;
        while(*ptr2) {
            if(*ptr2 == '\"') {
                if(get_start) {
                    *ptr2 = '\0';
                    break;
                } else {
                    get_start=1;
                    url_ptr = ptr2+1;
                }
            }
            ptr2++;
        }
        log_message(LOG_INFO, "id=%s url=%s g_devId=%s", id_ptr, url_ptr, g_devId);
        if (strcmp(id_ptr, g_devId) != 0) {
            add_resource(id_ptr, url_ptr);
        }
        cnt++;
        ptr = ptr2+1;
    }
    return cnt;
}

int parse_response(char *string)
{
    char *ptr=NULL, *r_ptr=NULL;
    char ret_str[8]={0};

    ptr = strstr(string, "\"ret\":");
    if (!ptr) {
        return -1;
    }

    ptr += 6;
    while(*ptr==' ') {
        ptr++;
    }

    r_ptr = ptr;

    while(*ptr){
        if(*ptr==','||*ptr=='}') {
            if(ptr-r_ptr>7){
                return -1;
            }
            memcpy(ret_str, r_ptr, ptr-r_ptr);
            ret_str[ptr-r_ptr]='\0';
            return atoi(ret_str);
        }
        ptr++;
    }

    return -1;
}

int new_resource_report(int port)
{
    int ret;
    char *resp=NULL;
    char content[4096]={0};
    char url[256]={0};
    const char *content_fmt="{\"type\":%d,\"deviceId\":\"%s\",\"resId\":%s,\"url\":\"%s\",\"cap\":%d}";

    if (check_resId(g_resId) < 0) {
        return -1;
    }

    build_srv_url(url, port, g_resId);

    snprintf(content, 4096, content_fmt, MSG_NEW_RESOUCE, get_device_id(), g_resId, url, 2);
    content[4095]=0;
    log_message (LOG_INFO, "===%s", content);

    resp = http_post(get_zb_srv_url(), content);
    if (!resp) {
        return 0;
    }
    log_message(LOG_INFO, "resp=%s", resp);

    ret = parse_response(resp);

    if (resp) {
        free(resp);
    }

    return ret;
}

int resource_down_report(void)
{
    int ret;
    char *resp=NULL;
    char content[4096]={0};
    const char *content_fmt="{\"type\": %d,\"deviceId\": \"%s\",\"resId\":%s}";

    if (check_resId(g_resId) < 0) {
        return -1;
    }

    snprintf(content, 4096, content_fmt, MSG_RESOUCE_DOWN, get_device_id(), g_resId);
    content[4095]=0;
    log_message (LOG_INFO, "===%s", content);

    resp = http_post(get_zb_srv_url(), content);
    if (!resp) {
        return 0;
    }
    log_message(LOG_INFO, "resp=%s", resp);

    ret = parse_response(resp);

    if (resp) {
        free(resp);
    }

    return ret;
}

int new_connection_report(const char *src)
{
    int ret;
    char *resp=NULL;
    char content[4096]={0};
    const char *content_fmt="{\"type\": %d,\"deviceId\": \"%s\", \"src\": \"%s\", \"resId\":%s}";

    if (check_resId(g_resId) < 0) {
        return -1;
    }

    strcpy(g_src, src);

    snprintf(content, 4096, content_fmt, MSG_NEW_CONN, get_device_id(), src, g_resId);
    content[4095] = 0;
    log_message (LOG_INFO, "===%s", content);

    resp = http_post(get_zb_srv_url(), content);
    if (!resp) {
        return 0;
    }
    log_message(LOG_INFO, "resp=%s", resp);

    ret = parse_response(resp);

    if (resp) {
        free(resp);
    }

    return ret;
}

int connection_down_report(unsigned int totalBytes)
{
    int ret;
    char *resp=NULL;
    char content[4096]={0};
    const char *content_fmt="{\"type\": %d,\"deviceId\": \"%s\", \"src\": \"%s\", \"resId\":%s, \"totalBytes\":%d}";

    if (check_resId(g_resId) < 0) {
        return -1;
    }

    snprintf(content, 4096, content_fmt, MSG_CONN_DOWN, get_device_id(), g_src, g_resId, totalBytes);
    content[4095]=0;
    log_message (LOG_INFO, "===%s", content);

    resp = http_post(get_zb_srv_url(), content);
    if (!resp) {
        return 0;
    }
    log_message(LOG_INFO, "resp=%s", resp);

    ret = parse_response(resp);

    if (resp) {
        free(resp);
    }

    return ret;
}

/* get zb source list from server */
int get_resource_list(const char* path, const char* host)
{
    int ret;
    char *resp=NULL;
    char content[4096]={0};
    const char *content_fmt="{\"type\": %d,\"deviceId\": \"%s\",\"path\": \"%s\",\"host\": \"%s\"}";

    if (!path || !host) {
        return -1;
    }

    snprintf(content, 4096, content_fmt, MSG_GET_RESOURCE, get_device_id(), path, host);
    content[4095]=0;
    log_message (LOG_INFO, "===%s", content);

    resp = http_post(get_zb_srv_url(), content);
    if (!resp) {
        return -1;
    }
    log_message(LOG_INFO, "resp=%s", resp);

    ret = parse_resource_list(resp);

    if (resp) {
        free(resp);
    }

    return ret;
}

int p2p_connect_setup(void)
{
    struct res_s *res=res_list;
    int fd=-1;
    int port=0;
    char host[MAX_HOST_LEN]={0}, path[MAX_PATH_LEN]={0};
    char lpbuf[BUFFER_SIZE*2]={0};

    while(res) {
        if (parse_url(res->url, host, &port, path) < 0) {
            res = res->next;
            continue;
        }

        fd = opensock(host, port, NULL);
        if (fd <= 0) {
            log_message (LOG_ERR, "connect to %s failed!", res->url);
            res = res->next;
            continue;
        }

        sprintf(lpbuf, HTTP_GET, path, host, port);
        if (http_tcpclient_send(fd, lpbuf, strlen(lpbuf)) < 0) {
            log_message(LOG_ERR, "p2p_connect_setup() send http request failed!\n");
            close(fd);
            continue;
        }

        log_message (LOG_CONN, "[SLAVE] connected to %s fd=%d ", res->url, fd);
        new_connection_report(res->devId);
        break;
    }

    return fd;
}

/*phicomm add*/
#define TRANSMISSION_PORT 6789
int transmission_connect_setup(void)
{
     int fd=-1;
     struct sockaddr_in addr;

     fd = socket(AF_INET, SOCK_STREAM, 0);
     if(fd <0)
     {
          perror("socket");
          return -1;
     }

     bzero(&addr, sizeof(addr));
     addr.sin_family = AF_INET;
     addr.sin_port = htons(TRANSMISSION_PORT);
     addr.sin_addr.s_addr = htonl(INADDR_ANY);	

     if(connect(fd, &addr, sizeof(addr))<0)
     	{
     	   perror("connect error");
	   close(fd);
	   return -1;
     	}
	 
     return fd;
}
