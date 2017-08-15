/* This file is used to buid packet as defined and send to server.
 * */
#include "iotc.h"

/* TODO: the path should not be gateway */
#define HTTP_HEAD_FIX "POST /gateway HTTP/1.1\r\n\
User-Agent: iotc/1.0\r\n\
Accept: text/html, application/json\r\n\
Accept-Language: en-US\r\n\
Accept-Encoding: gzip, deflate\r\n\
Connection: keep-alive\r\n\
Content-Type: application/json\r\n"

#define HTTP_HEAD_HOST "Host: %s\r\n"
#define HTTP_HEAD_CON_LEN "Content-Length: %5d\r\n\r\n"


#define MAX_HOST_STR_LEN 512
static char g_hostStr[MAX_HOST_STR_LEN];
static int g_hostHdrLen=-1;


#define HEAD_FIX_LEN (strlen(HTTP_HEAD_FIX))
#define HEAD_CON_LEN_LEN (25)
#define HEAD_HOST_LEN (g_hostHdrLen)


extern bool isPublicIp;
extern bool bemaster;
extern char g_zburl[64];
extern char iotc_wan_ip[MAX_IP_LEN];
extern char iotc_stun_ip[MAX_IP_LEN];
extern unsigned long long  rxBytesStart;
extern unsigned long long  rxBytesEnd;
extern unsigned long long  txBytesStart;
extern unsigned long long  txBytesEnd;

void iotc_genHostStr(char *server)
{
    g_hostHdrLen = snprintf(g_hostStr, sizeof(g_hostStr)-1, HTTP_HEAD_HOST, server);
    g_hostStr[MAX_HOST_STR_LEN-1] = '\0';
}

static int iotc_getHttpHeadLen()
{
    if(HEAD_HOST_LEN == -1) 
    {
        return -1;
    }

    return (HEAD_FIX_LEN+HEAD_HOST_LEN+HEAD_CON_LEN_LEN);
}

extern uint32_t g_devId;

static int iotc_addHttpHeader(char *buf, int conLen)
{
    strncpy(buf, HTTP_HEAD_FIX, HEAD_FIX_LEN);
    strncpy(buf+HEAD_FIX_LEN, g_hostStr, HEAD_HOST_LEN);
    snprintf(buf+HEAD_FIX_LEN+HEAD_HOST_LEN, HEAD_CON_LEN_LEN, HTTP_HEAD_CON_LEN, conLen);
    *(buf+HEAD_FIX_LEN+HEAD_HOST_LEN+HEAD_CON_LEN_LEN-1)='\n';

    return 0;
}

static int iota_addIoTHeader(char *buf, int conLen)
{
    struct fxIoT_head *head = (struct fxIoT_head*)buf;
    memset(head, 0, sizeof(struct fxIoT_head));

    head->length = htons(conLen);

    iotc_debug("head=%x", *head);

    return 0;
}


int new_resource_report(int port, char *resId)
{
    int ret;
    char *resp=NULL;
    char content[4096]={0};
    char url[256]={0};
    const char *content_fmt="{\"type\":%d,\"deviceId\":\"%s\",\"resId\":%s,\"url\":\"%s\",\"cap\":%d}";

    sprintf(url, "http://%s:%d/%s", iotc_stun_ip, port, resId);
    snprintf(content, 4096, content_fmt, MSG_NEW_RESOUCE, g_devId, resId, url, 2);
    content[4095]=0;
    iotc_debug ("===%s", content);

    resp = http_post(g_zburl, content);
    if (!resp) {
        return 0;
    }
    iotc_debug("resp=%s", resp);

    ret = parse_response(resp);

    if (resp) {
        free(resp);
    }

    return ret;
}


/* success: return http body length 
 * failure: return -1 */
static int iotc_buildDevOnlineData(char *buf, int maxLen)
{
    int ret=-1;
    cJSON *jsonRoot=NULL;
    char *s=NULL;

    iotc_debug("Enter.");

    /*create json string root*/
    jsonRoot = cJSON_CreateObject();
    if (!jsonRoot) 
    {
        iotc_debug("%s[%d]: get json_root faild !", __func__, __LINE__);
        return -1;
    }

    cJSON_AddNumberToObject(jsonRoot, "type", MSG_DEV_ONLINE_RSP); 
    cJSON_AddStringToObject(jsonRoot, "manufactureSN", g_manufactureSN);
    cJSON_AddStringToObject(jsonRoot, "manufacture", g_manufacture);
    cJSON_AddStringToObject(jsonRoot, "publicIpAddr", iotc_stun_ip);
    cJSON_AddNumberToObject(jsonRoot, "upnpPort", 10008);

    s = cJSON_PrintUnformatted(jsonRoot);
    if (s)
    {
        ret=snprintf(buf, maxLen, "%s", s);
        buf[maxLen-1] = '\0';
        iotc_debug("ret=%d,buf=%s\n", ret, buf);
        free(s);    
    }
    else
    {
        iotc_error("convert json to string format failed!");
    }

    cJSON_Delete(jsonRoot);
    iotc_debug("Exit.");
    return ret;
}

/* success: return http body length 
 * failure: return -1 */
static int iotc_buildSetRspData(char *buf, int maxLen, int cmdId, int retCode, cJSON *jsonDevData)
{
    int ret=-1;
    cJSON *jsonRoot=NULL;
    char *s=NULL;
    int needDetachJsonDevData=0;

    iotc_error("Enter.");

    /*create json string root*/
    if ((jsonRoot=cJSON_CreateObject()) == NULL)
    {
        iotc_error("create json root node failed!");
        goto exit;
    }

    cJSON_AddStringToObject(jsonRoot, "type", "rsp_set");
    cJSON_AddNumberToObject(jsonRoot, "commandId", cmdId);
    cJSON_AddNumberToObject(jsonRoot, "deviceId", g_devId);
    cJSON_AddNumberToObject(jsonRoot, "ret", retCode);
/*
    if (0 == retCode)
    {
        if (jsonDevData)
        {
            cJSON_AddItemToObject(jsonRoot, "devData", jsonDevData);
            needDetachJsonDevData=1;
        }
    }
*/
    if ((s=cJSON_PrintUnformatted(jsonRoot)) == NULL)
    {
        iotc_error("convert json to string format failed!");
        goto exit1;
    }

    ret=snprintf(buf, maxLen, "%s", s);
    buf[maxLen-1] = '\0';
    iotc_debug("buf=%s\n", buf);
    free(s);
/*
    if (needDetachJsonDevData == 1)
    {
        cJSON_DetachItemFromObject(jsonRoot, "devData");
    }
*/
exit1:
    cJSON_Delete(jsonRoot);
exit:
    iotc_debug("Exit.");
    return ret;
}

static int iotc_buildDevBwInfoData(char *buf, int maxLen)
{
    int ret=-1;
    int uploadbw,downloadbw;
    cJSON *jsonRoot=NULL;
    char *s=NULL;

    iotc_debug("Enter.");

    /*create json string root*/
    jsonRoot = cJSON_CreateObject();
    if (!jsonRoot) 
    {
        iotc_debug("%s[%d]: get json_root faild !", __func__, __LINE__);
        return -1;
    }

    uploadbw = ((txBytesEnd - txBytesStart)*8)>>20;
    downloadbw = ((rxBytesEnd - rxBytesStart)*8)>>20;

    cJSON_AddNumberToObject(jsonRoot, "type", MSG_BW_INFO); 
    cJSON_AddNumberToObject(jsonRoot, "deviceId", g_devId);
    cJSON_AddStringToObject(jsonRoot, "ipAddr", iotc_wan_ip);
    cJSON_AddNumberToObject(jsonRoot, "uplinkBw", uploadbw/10);
    cJSON_AddNumberToObject(jsonRoot, "downlinkBw", downloadbw/10);

    s = cJSON_PrintUnformatted(jsonRoot);
    if (s)
    {
        ret=snprintf(buf, maxLen, "%s", s);
        buf[maxLen-1] = '\0';
        iotc_debug("ret=%d,buf=%s\n", ret, buf);
        free(s);    
    }
    else
    {
        iotc_error("convert json to string format failed!");
    }

    cJSON_Delete(jsonRoot);
    iotc_debug("Exit.");
    return ret;
}


static int iotc_buildDevTopoInfoData(char *buf, int maxLen)
{
    int ret=-1;
    cJSON *jsonRoot=NULL;
    char *s=NULL;

    iotc_debug("Enter.");

    /*create json string root*/
    jsonRoot = cJSON_CreateObject();
    if (!jsonRoot) 
    {
        iotc_debug("%s[%d]: get json_root faild !", __func__, __LINE__);
        return -1;
    }

    cJSON_AddNumberToObject(jsonRoot, "type", MSG_NET_INFO); 
    cJSON_AddNumberToObject(jsonRoot, "deviceId", g_devId);
    cJSON_AddStringToObject(jsonRoot, "publicIpAddr", iotc_stun_ip);
    cJSON_AddNumberToObject(jsonRoot, "beMaster", isPublicIp?1:bemaster);

    s = cJSON_PrintUnformatted(jsonRoot);
    if (s)
    {
        ret=snprintf(buf, maxLen, "%s", s);
        buf[maxLen-1] = '\0';
        iotc_debug("ret=%d,buf=%s\n", ret, buf);
        free(s);    
    }
    else
    {
        iotc_error("convert json to string format failed!");
    }

    cJSON_Delete(jsonRoot);
    iotc_debug("Exit.");
    return ret;
}


static int iotc_sendHttpBuf(char *buf, int len)
{
    int ret=-1;

    iotc_debug("Enter.");

    if ( NULL==buf || len < 10 )
    {
        iotc_error("param error! len=%d", len);
        return -1;
    }

    if (-1 == is_socket_connected(iotc_monitor_http_uloop_fd.fd))
    {
        close(iotc_monitor_http_uloop_fd.fd);
        //socket_init();
    }

    ret=send(iotc_monitor_http_uloop_fd.fd, buf, len, 0);
    if (ret > 0)
    {
        iotc_debug("send http buf succeed!");
        return 0;
    }
    else if (ret == -1)
    {
        iotc_error("send msg failed! %s!", strerror(errno));
        close(iotc_monitor_http_uloop_fd.fd);
    }
    else
    {
        iotc_error("send msg failed! ret=%d, %s.", ret, strerror(errno));
        return -1;
    }
    iotc_debug("Exit.");
}

static int iotc_sendManageBuf(char *buf, int len)
{
    int ret=-1;

    iotc_debug("Enter.");

    if ( NULL==buf || len < 10 )
    {
        iotc_error("param error! len=%d", len);
        return -1;
    }

    if (-1 == is_socket_connected(iotc_monitor_manage_uloop_fd.fd))
    {
        close(iotc_monitor_manage_uloop_fd.fd);
        //socket_init();
    }

    ret=send(iotc_monitor_manage_uloop_fd.fd, buf, len, 0);
    if (ret > 0)
    {
        iotc_debug("send msg buf succeed!");
        return 0;
    }
    else if (ret == -1)
    {
        iotc_error("send msg failed! %s!", strerror(errno));
        close(iotc_monitor_manage_uloop_fd.fd);
    }
    else
    {
        iotc_error("send msg failed! ret=%d, %s.", ret, strerror(errno));
        return -1;
    }
    iotc_debug("Exit.");
}

int iotc_sendDevOnlineMsg()
{
    int conLen=-1;
    int cmdId=0;
    char manageBuf[SEND_MAX_BUF_LEN]={0};

    iotc_debug("Enter.");

    /* reserve headLen bytes for http head */
    if ((conLen=iotc_buildDevOnlineData(manageBuf, SEND_MAX_BUF_LEN)) < 0)
    {
        iotc_error("failed to build http body!");
        return -1;
    }

    if (iotc_sendManageBuf(manageBuf, conLen) < 0)
    {
        iotc_error("send http pkt failed!");
        return -1;
    }
/*
    if (iotcSess_waitRsp(MSG_DEV_ONLINE_RSP, cmdId) != 0)
    {
        iotc_error("malloc failed!");
        return -1;
    }
*/
    iotc_debug("Exit.");

    return 0;
}

int iotc_sendDevBwInfoMsg()
{
    int conLen=-1;
    char manageBuf[SEND_MAX_BUF_LEN]={0};

    iotc_debug("Enter.");

    memset(manageBuf, 0,sizeof(manageBuf));
    if ((conLen=iotc_buildDevBwInfoData(manageBuf, SEND_MAX_BUF_LEN)) < 0)
    {
        iotc_error("failed to build http body!");
        return -1;
    }
    if (iotc_sendManageBuf(manageBuf, conLen) < 0)
    {
        iotc_error("send http pkt failed!");
        return -1;
    }

    memset(manageBuf, 0,sizeof(manageBuf));
    if ((conLen=iotc_buildDevTopoInfoData(manageBuf, SEND_MAX_BUF_LEN)) < 0)
    {
        iotc_error("failed to build http body!");
        return -1;
    }
    if (iotc_sendManageBuf(manageBuf, conLen) < 0)
    {
        iotc_error("send http pkt failed!");
        return -1;
    }
    iotc_debug("Exit.");

    return 0;
}

int iotc_sendSetRspMsg(int cmdId, int retCode, cJSON *jsonDevData)
{
    int ret=-1;
    int headLen=0, conLen=-1;
    char httpBuf[SEND_MAX_BUF_LEN]={0};

    iotc_debug("Enter.");

    if ((headLen=iotc_getHttpHeadLen()) == -1)
    {
        iotc_error("iot server string is missing!");
        return -1;
    }

    /* reserve headLen bytes for http head */
    if ((conLen=iotc_buildSetRspData(&httpBuf[headLen],
                                     SEND_MAX_BUF_LEN-headLen,
                                     cmdId,
                                     retCode,
                                     jsonDevData)) < 0)
    {
        iotc_error("failed to build http body!");
        return -1;
    }

    if ((ret=iotc_addHttpHeader(httpBuf, conLen)) != 0)
    {
        iotc_error("failed to build http head!");
        return -1;
    }

    iotc_debug("httpBuf=%s", httpBuf);

    iotc_sendHttpBuf(httpBuf, headLen+conLen);

    iotc_debug("Exit.");

    return ret;
}
