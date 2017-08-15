#include <stdio.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include "iotc.h"

struct sockaddr_in server_addr;
bool bemaster = false;

extern char iotc_server_ip[];
extern int iotc_server_port; 
extern SpeedTestType speedTestEnable;
extern struct uloop_timeout g_timeoutTm1;
extern struct uloop_timeout g_timeoutTm2;
extern struct uloop_timeout g_timeoutTm3;
extern struct uloop_timeout g_timeoutTm4;

#define FLV_MESSAGE_BACKLOG 3
#define MAX_CONNECTION_NUMBER 50

static int socket_create(void)
{
    iotc_debug("Enter.");

#ifdef HTTP_SERVER
    if ((iotc_monitor_http_uloop_fd.fd = socket(AF_INET,SOCK_STREAM,0)) < 0)
    {
        iotc_error("failed to socket! %s", strerror(errno));
        return -1;
    }
    iotc_debug("socket create succeed, fd=%d", iotc_monitor_http_uloop_fd.fd);
#endif

    if ((iotc_monitor_manage_uloop_fd.fd = socket(AF_INET,SOCK_STREAM,0)) < 0)
    {
        iotc_error("failed to socket! %s", strerror(errno));
        return -1;
    }
    iotc_debug("socket create succeed, manage fd=%d", iotc_monitor_manage_uloop_fd.fd);

    iotc_debug("Exit.");
    return 0;
}

static int socket_connect(void)
{
    iotc_debug("Enter.");

    memset(&server_addr,0,sizeof(server_addr));
    server_addr.sin_family      = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(iotc_server_ip);
    server_addr.sin_port        = htons(iotc_server_port);

    while (1)
    {
        if (connect(iotc_monitor_manage_uloop_fd.fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == 0)
        {
            iotc_debug("connect to manage server succeed.");
            break;
        }

        sleep(5);
        iotc_debug("trying to connect to manage server...");
    }
#ifdef HTTP_SERVER
    server_addr.sin_port        = htons(80);
    while (1)
    {
        if (connect(iotc_monitor_http_uloop_fd.fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == 0)
        {
            iotc_debug("connect to http server succeed.");
            break;
        }

        sleep(5);
        iotc_debug("trying to connect to http server...");
    }
#endif
}

int connection_init(void)
{
    int res=-1;
    int keepalive=1;      // 开启keepalive属性
    int keepidle=30;     // 如该连接在30秒内没有任何数据往来,则进行探测
    int keepinterval=10;  // 探测时发包的时间间隔为10秒
    int keepcount=3;      // 探测尝试的次数.如果第1次探测包就收到响应了,则后2次的不再发.
    int fd=-1;

    iotc_debug("Enter.");

    if ( 0 != socket_create())
    {
        iotc_debug("socket_create failed!");
        return -1;
    }

    socket_connect();
#ifdef HTTP_SERVER
    fd=iotc_monitor_http_uloop_fd.fd;
    if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (void *)&keepalive, sizeof(keepalive)) < 0)
    {
        iotc_error("setsockopt SO_KEEPALIVE failed! %s", strerror(errno));
    }
    if (setsockopt(fd, SOL_TCP, TCP_KEEPIDLE, (void*)&keepidle, sizeof(keepidle)) < 0)
    {
        iotc_error("setsockopt TCP_KEEPIDLE failed! %s", strerror(errno));
    }
    if (setsockopt(fd, SOL_TCP, TCP_KEEPINTVL, (void *)&keepinterval, sizeof(keepinterval)) < 0)
    {
        iotc_error("setsockopt TCP_KEEPINTVL failed! %s", strerror(errno));
    }
    if (setsockopt(fd, SOL_TCP, TCP_KEEPCNT, (void *)&keepcount, sizeof(keepcount)) < 0)
    {
        iotc_error("setsockopt TCP_KEEPCNT failed! %s", strerror(errno));
    }
#endif
    fd=iotc_monitor_manage_uloop_fd.fd;
    if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (void *)&keepalive, sizeof(keepalive)) < 0)
    {
        iotc_error("setsockopt SO_KEEPALIVE failed! %s", strerror(errno));
    }
    if (setsockopt(fd, SOL_TCP, TCP_KEEPIDLE, (void*)&keepidle, sizeof(keepidle)) < 0)
    {
        iotc_error("setsockopt TCP_KEEPIDLE failed! %s", strerror(errno));
    }
    if (setsockopt(fd, SOL_TCP, TCP_KEEPINTVL, (void *)&keepinterval, sizeof(keepinterval)) < 0)
    {
        iotc_error("setsockopt TCP_KEEPINTVL failed! %s", strerror(errno));
    }
    if (setsockopt(fd, SOL_TCP, TCP_KEEPCNT, (void *)&keepcount, sizeof(keepcount)) < 0)
    {
        iotc_error("setsockopt TCP_KEEPCNT failed! %s", strerror(errno));
    }

    iotc_debug("Exit.");
    return 0;
}


/* to check if the socket is still up: */
int is_socket_connected(fd)
{
    int error=0;
    socklen_t len=sizeof(error);
    int ret=0;

    iotc_debug("Enter.");

    ret=getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len);

    if (ret != 0)  
    {
        iotc_debug("failed to get socket error code: %s", strerror(ret));
        return -1;
    }

    if (error != 0)  
    {
        iotc_error("socket error: %s", strerror(errno));
        return -1;
    }

    iotc_debug("Exit.");
    return 0;
}

/* * Create a server endpoint of a connection. * Returns fd if all OK, <0 on error. */
int unix_socket_listen(const char *servername)
{ 
    int fd;
    struct sockaddr_un un; 
    if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
    {
        return(-1); 
    }
    int len, rval; 
    unlink(servername);               /* in case it already exists */ 
    memset(&un, 0, sizeof(un)); 
    un.sun_family = AF_UNIX; 
    strcpy(un.sun_path, servername); 
    len = offsetof(struct sockaddr_un, sun_path) + strlen(servername); 
    /* bind the name to the descriptor */ 
    if (bind(fd, (struct sockaddr *)&un, len) < 0)
    { 
        rval = -2; 
    } 
    else
    {
        if (listen(fd, MAX_CONNECTION_NUMBER) < 0)    
        { 
            rval =  -3; 
        }
        else
        {
            return fd;
        }
    }
    int err;
    err = errno;
    close(fd); 
    errno = err;
    return rval;    
}

int unix_socket_accept(int listenfd, uid_t *uidptr)
{
    int clifd, len, rval;
    time_t staletime;
    struct sockaddr_un un;
    struct stat statbuf;
    len = sizeof(un);
    if ((clifd = accept(listenfd, (struct sockaddr *)&un, &len)) < 0) 
    {
        return(-1);
    }
    /* obtain the client's uid from its calling address */
    len -= offsetof(struct sockaddr_un, sun_path);  /* len of pathname */
    un.sun_path[len] = 0; /* null terminate */
    if (stat(un.sun_path, &statbuf) < 0)
    {
        rval = -2;
    }
    else
    {
        if (S_ISSOCK(statbuf.st_mode))
        {
            if (uidptr != NULL) *uidptr = statbuf.st_uid;    /* return uid of caller */ 
            unlink(un.sun_path);       /* we're done with pathname now */ 
            return clifd;
        }
        else
        {
            rval = -3;     /* not a socket */
        }
    }
    int err;
    err = errno; 
    close(clifd);
    errno = err;
    return(rval);
}
 
void unix_socket_close(int fd)
{
    close(fd);
}

void *ipc_process_task_thread(void *arg)
{
    int size;
    int port;
    uid_t uid;
    char rvbuf[256];
    cJSON *json=NULL, *json_port=NULL;
    int listenfd,connfd; 

    printids(" new thread: ");

    listenfd = unix_socket_listen(FLV_MAIN_ADDR);
    if(listenfd<0)
    {
        iotc_error("when listening...\n");
        return 0;
    }
    iotc_debug("Finished listening...\n",errno);

    while(1)
    {
        connfd = unix_socket_accept(listenfd, &uid);
        unix_socket_close(listenfd);
        if(connfd<0)
        {
            iotc_error("when accepting...\n");
            return 0;
        }
        iotc_debug("Begin to recv/send...\n");  

        size = recv(connfd, rvbuf, 256, 0);   
        if(size>=0)
        {
            iotc_debug("Recieved Data[%d]:%s.\n",size,rvbuf);

            /* parse json_buf */
            if ((json=cJSON_Parse(rvbuf)) == NULL)
            {
                iotc_error("json parse unix domain rxbuf failed!\n");
                return -1;
            }

            /* parse item "port" */ 
            if ((json_port=cJSON_GetObjectItem(json, "port")) == NULL)
            {
                iotc_error("port is missing!");
                cJSON_Delete(json);  
                return -1;
            }

            if (json_port->type != cJSON_Number)
            {
                iotc_error("port's value is missing or in wrong format!");
                cJSON_Delete(json);
                return -1;
            }

            iotc_debug("port=%d", json_port->valueint);

            upnpc_init(json_port->valueint);
            new_resource_report(json_port->valueint);
        }
        if(size==-1)
        {
            iotc_error("when recieving Data:%s.\n",strerror(errno));
            break;
        }
        sleep(1);
        unix_socket_close(connfd);
    }

    iotc_debug("Client exited.\n");
    pthread_exit(0);
}

void *speed_test_process_task_thread(void *arg)
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

        sleep(3);
        uloop_timeout_set(&g_timeoutTm1, 5000);
        uloop_timeout_set(&g_timeoutTm2, 15000);
        uloop_timeout_set(&g_timeoutTm3, 20000);
        uloop_timeout_set(&g_timeoutTm4, 30000);

        iotc_debug("trying to connect to speed test server...");
    }

    uloop_timeout_set(&g_timeoutTm1, 5000);
    uloop_timeout_set(&g_timeoutTm2, 15000);
    uloop_timeout_set(&g_timeoutTm3, 20000);
    uloop_timeout_set(&g_timeoutTm4, 30000);

    speedTestEnable = SPEED_TEST_START;
    while(speedTestEnable){
        len=recv(testfd, buf, RECV_MAX_BUF_LEN, 0);
        if ((len <= 0))
        {
            iotc_error("recv from fd(%d) error: %s, len = %d", testfd, strerror(errno), len);
        }
    }

    speedTestEnable = SPEED_TEST_START;
    while(speedTestEnable){
        len=send(testfd, buf, RECV_MAX_BUF_LEN, 0);
        if ((len <= 0))
        {
            iotc_error("recv from fd(%d) error: %s, len = %d", testfd, strerror(errno), len);
        }
    }
    close(testfd);

    iotc_sendDevBwInfoMsg();
    
    pthread_exit(0);
}


void *check_available_process_task_thread(int port)
{
    int sin_len;
    char message[64];
    int socket_descriptor;
    struct sockaddr_in sin;

    iotc_debug("Waiting for data form sender. port:%d\n",port);
    
    bzero(&sin,sizeof(sin));
    sin.sin_family=AF_INET;
    sin.sin_addr.s_addr=htonl(INADDR_ANY);
    sin.sin_port=htons(port);
    sin_len=sizeof(sin);
    
    socket_descriptor=socket(AF_INET,SOCK_DGRAM,0);
    bind(socket_descriptor,(struct sockaddr *)&sin,sizeof(sin));
    while(1)
    {
        recvfrom(socket_descriptor,message,sizeof(message),0,(struct sockaddr *)&sin,&sin_len);  
        printf("Response from server:%s\n",message);
        if(strncmp(message,"OK",2) == 0)
        {
            bemaster = true;
            printf("Sender has told me OK\n");
            break;
        }
    }
    close(socket_descriptor);

    pthread_exit(0);
}


