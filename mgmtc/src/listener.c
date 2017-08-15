#include "iotc.h"
#include "cJSON.h"

extern char iotc_server_ip[MAX_IP_LEN];
extern int iotc_server_port;

extern int iotc_handleServerPkt(char *recvbuf);

static int iotc_readDataFromSocket(int fd, char *buf)
{
    int len=-1;

    iotc_debug("Enter.");

    len=recv(fd, buf, RECV_MAX_BUF_LEN, 0);

    if ((len <= 0))
    {
        iotc_error("recv from fd(%d) error: %s, len = %d", fd, strerror(errno), len);
    }

    iotc_debug("Exit.");
    return len;
}

static void iotc_recvServerData(struct uloop_fd *u, unsigned int events)
{
    int len=0;
    char recv_buf[RECV_MAX_BUF_LEN] = {0};
    
    iotc_debug("Enter.");

    len=iotc_readDataFromSocket(u->fd, recv_buf);
    iotc_debug("len=%d recv_buf=%s", len, recv_buf);
    if (len > 0)
    {
        iotc_handleServerPkt(recv_buf);
    }
    else
    {
        iotc_debug("%s[%d]: recv_buf_len = %d, no need to handle ", __func__, __LINE__, len);
    }

    iotc_debug("Exit.");
}

static void iotc_recvServerManageData(struct uloop_fd *u, unsigned int events)
{
    int len = 0;
    char recv_buf[RECV_MAX_BUF_LEN] = {0};
    
    iotc_debug("Enter");
    memset(recv_buf, 0, RECV_MAX_BUF_LEN);
    len = iotc_readDataFromSocket(u->fd, recv_buf);
    printf("\n\n");
    iotc_debug("len=%d recv_buf=%s", len, recv_buf);
    printf("\n\n");

    if (len > 0)
    {
        cloudc_parse_receive_info(recv_buf);
    }
    else if(0 == len)
    {
        iotc_debug(": recv_buf_len = %d, %s, restart fxagent ", len, strerror(errno));
        is_socket_connected(u->fd);
        close(u->fd);
        int fxagentPid = getpid();
        char cmd1[128] = {0};
        char cmd2[128] = {0};
        //snprintf(cmd1, sizeof(cmd1), "fxagent %s:%d &", iotc_server_ip, iotc_server_port);
        snprintf(cmd1, sizeof(cmd1), "/etc/init.d/mgmtc start");
        system(cmd1);
        snprintf(cmd2, sizeof(cmd2), "kill -9 %d", fxagentPid);
        system(cmd2);
    }
    else
    {
        iotc_debug(": recv_buf_len = %d, no need to handle", len);
    }

    iotc_debug("Exit");
}

struct uloop_fd iotc_monitor_http_uloop_fd = {
    .cb = iotc_recvServerData,
    .fd = -1
};

struct uloop_fd iotc_monitor_manage_uloop_fd = {
    .cb = iotc_recvServerManageData,
    .fd = -1
};


