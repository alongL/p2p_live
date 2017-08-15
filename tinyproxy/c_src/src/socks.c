#include <stdlib.h>
#include <time.h>

#include "main.h"
#include "log.h"
#include "sock.h"
#include "socks.h"

#define BIND_TRY_NUM 20
#define URL_MAX_LEN 2048

extern char g_resId[RESID_LEN];

void get_master_url(char *url)
{
    int fd,size;

    fd=open("/var/flv_d_srv",O_RDONLY);
    size=read(fd, url, URL_MAX_LEN);
    close(fd);
    url[2047] = '\0';
}

int initUnixDomainServerSocket(char *path)
{
    struct sockaddr_un serverAddr;
    int fd, rc;

    umask(0);
    unlink(path);


    if ((fd = socket(AF_LOCAL, SOCK_STREAM, 0)) < 0)
    {
        log_message (LOG_ERR, "Could not create socket");
        return fd;
    }

    /*
     * Bind my server address and listen.
     */
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sun_family = AF_LOCAL;
    strncpy(serverAddr.sun_path, path, sizeof(serverAddr.sun_path));

    rc = bind(fd, (struct sockaddr *) &serverAddr, sizeof(serverAddr));
    if (rc != 0)
    {
        log_message (LOG_ERR, "bind to %s failed, rc=%d errno=%d", path, rc, errno);
        close(fd);
        return -1;
    }

    rc = listen(fd, FLV_MESSAGE_BACKLOG);
    if (rc != 0)
    {
        log_message (LOG_ERR, "listen to %s failed, rc=%d errno=%d", path, rc, errno);
        close(fd);
        return -1;
    }

    log_message (LOG_CONN, "flv msg socket opened and ready (fd=%d)", fd);

    return fd;
}

int connect_to_master(char *path, int port)
{
    int fd=-1,size;
    char rvbuf[256];
    struct sockaddr_un serverAddr;
    int rc;

    memset(rvbuf,0,sizeof(rvbuf));

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
    {
        log_message (LOG_ERR, "Could not create socket");
        return -1;
    }

    if ((rc = fcntl(fd, F_SETFD, FD_CLOEXEC)) != 0)
    {
        log_message (LOG_ERR, "set close-on-exec failed, rc=%d errno=%d", rc, errno);
        close(fd);
        return -1;
    }

    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sun_family = AF_UNIX;
    strncpy(serverAddr.sun_path, path, sizeof(serverAddr.sun_path));
    rc = connect(fd, (struct sockaddr *) &serverAddr, sizeof(serverAddr));
    if (rc != 0)
    {
        log_message (LOG_ERR, "connect to %s failed, rc=%d err=%s", path, rc, strerror(errno));
        close(fd);
        return -1;
    }
    else
    {
        log_message (LOG_CONN, "[SLAVE] connected to master fd=%d ", fd);
    }

    sprintf(rvbuf, "{\"port\":%d,\"resId\":\"%s\"}", MSG_NEW_RESOUCE, g_resId);
    size = send(fd, rvbuf, strlen(rvbuf), 0);
    if(size>=0)
    {
        printf("Data[%d] Sended:%s.\n",size,rvbuf);
    }
    if(size==-1)
    {
        log_message (LOG_ERR, "when Sending Data:%s.\n",strerror(errno));     
    }
    rc = close(fd);
    return rc;
}

int init_flv_server(int *server_port)
{
    int fd=-1;  
    struct sockaddr_in server_addr;    
    int opt = 1;
    int i=0, start_port=FLV_SRV_PORT;

    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        log_message (LOG_ERR, "Could not create socket");
        exit(1);
    }

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
        log_message (LOG_ERR, "setsockopt err: %s", strerror(errno));
        exit(1);
    }

    for (i=0; i<BIND_TRY_NUM; i++) {
        bzero(&server_addr, sizeof(server_addr));
        server_addr.sin_family = AF_INET;         
        server_addr.sin_port = htons(start_port+i);
        server_addr.sin_addr.s_addr = htonl(INADDR_ANY);

        if (bind(fd, (struct sockaddr *)&server_addr, sizeof(struct sockaddr))== -1) {
            if (errno == EADDRINUSE) {
                continue;
            }
            log_message (LOG_ERR, "bind failed, errno=%s", strerror(errno));
            close(fd);
            exit(1);
        } else {
            *server_port = start_port+i;
            log_message (LOG_INFO, "service bind to port %d", *server_port);
            break;
        }
    }

    if (i==BIND_TRY_NUM) {
        log_message (LOG_ERR, "bind failed, with %d times.", BIND_TRY_NUM);
        close(fd);
        exit(1);
    }

    if (listen(fd, 5) == -1) {
        close(fd);
        log_message (LOG_ERR, "listen failed, errno=%d", errno);
        exit(1);
    }

    log_message (LOG_CONN, "flv server opened and ready (fd=%d)", fd);

    return fd;
}
