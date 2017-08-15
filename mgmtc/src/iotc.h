#ifndef __IOTC_H__
#define __IOTC_H__

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <libubox/uloop.h>
#include "cJSON.h"
#include "iotc_log.h"

#define MAX_IP_LEN 16
#define SEND_MAX_BUF_LEN 4096
#define RECV_MAX_BUF_LEN 4096
#define FLV_MAIN_ADDR "/var/flv_server"
#define MSG_NEW_RESOUCE     1

#define FXAGENT_HEAD_LEN (sizeof(struct fxIoT_head))

typedef enum {
    SPEED_TEST_STOP = 0,
    SPEED_TEST_START,
}SpeedTestType;

typedef enum {
    MSG_DEV_ONLINE_RSP=1,
    MSG_BW_INFO,
    MSG_NET_INFO,
    MSG_ALARM,
    MSG_ZB_RESOURCE,
    MSG_ZB_GET_LIST,
    MSG_ZB_COMFIRM,
    MSG_ZB_STOP,
    MSG_KEEP_ALIVE,
    MSG_UNKNOWN,
}AgentMsgType;

typedef struct fxIoT_head
{
    short int length;
    char cequence;
    char reserved;
}fxIoT_head;

extern struct uloop_fd iotc_monitor_http_uloop_fd;
extern struct uloop_fd iotc_monitor_manage_uloop_fd;
extern char g_manufacture[32];
extern char g_manufactureSN[64];


/* from glue.c */
int glue_init();
//char* glue_getDevData();
int glue_isMyself(char *manufacture, char *manufactureSN);
void glue_updateDevId(uint32_t devId, char *zburl);

/* from proto.c */
void iotc_genHostStr(char *server);
int iotc_sendDevOnlineMsg();
int iotc_sendSetRspMsg(int cmdId, int retCode, cJSON *jsonDevData);

/* from session.c */
int iotcSess_gotRsp(AgentMsgType msgType, unsigned int cmdId);
int iotcSess_waitRsp(AgentMsgType msgType, unsigned int cmdId);
#endif

