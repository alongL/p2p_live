#include "iotc.h"


static char* iotc_getHttpBody(char *recvbuf)
{
    char *body=NULL;

    iotc_debug("Enter.");
    body=strstr(recvbuf, "{");
    iotc_debug("Exit.");
    return body;
}

int cloudc_parse_receive_info(char *recvbuf)
{
    //char *http_body = NULL;
    //int data_len = 0, res_len = RECV_MAX_BUF_LEN;
    //char *msg_ptr = recvbuf;
    iotc_debug("%s[%d]: Enter", __func__, __LINE__);

    iotc_parseHttpBody(recvbuf);

#if 0
    while ((data_len = cloudc_parse_manage_header(msg_ptr)) > 0)
    {
        http_body = iotc_getHttpBody(&msg_ptr[FXAGENT_HEAD_LEN]);

        if (NULL != http_body)
        {
            //cloudc_parse_manage_body(http_body);
            iotc_parseHttpBody(http_body);
        }

        if (data_len>(res_len-FXAGENT_HEAD_LEN))
        {
            iotc_error("%s[%d]: recv length parse overflow!", __func__,__LINE__);
            return 0;
        }
        res_len = res_len-(data_len+FXAGENT_HEAD_LEN);

        if (res_len>0)
            msg_ptr += (FXAGENT_HEAD_LEN + data_len);
        else
            return 0;
    }
#endif
    iotc_debug("%s[%d]: Exit", __func__, __LINE__);
    return 0;
}

static int iotc_parseHttpHeader(char *recvbuf)
{
    iotc_debug("Enter.");
    /* TODO: */
    iotc_debug("Exit.");
    return 0;
}

int cloudc_parse_manage_header(char *recvbuf)
{
    iotc_debug("%s[%d]: Enter", __func__, __LINE__);
    /* need to parse http value firstly
     * such as return code
     * ...
     * if return code is ok, then return 0 and go on parse body value
     * */

    if (!recvbuf) 
    {
        return 0;
    }

    struct fxIoT_head *head = (struct fxIoT_head *)recvbuf;
    int len = 0;

    len = ntohs(head->length);
    iotc_debug("data_len:%d", len);

    if (len > 0)
    {
        return len;
    }

    iotc_debug("%s[%d]: Exit", __func__, __LINE__);
    return 0;
}

static int handle_devOnlineRsp(cJSON *json)
{
    cJSON *json_deviceId=NULL, *json_zburl=NULL;

    iotc_debug("Enter.");

    json_deviceId = cJSON_GetObjectItem(json, "deviceId");
    json_zburl = cJSON_GetObjectItem(json, "zburl");

    /* integrity and validity check */
    if(!json_deviceId || !json_zburl)
    {
        iotc_error("missing json param!");
        return -1;
    }

    if (json_deviceId->type != cJSON_Number||
        json_zburl->type != cJSON_String)
    {
        iotc_error("param type is wrong!");
        return -1;
    }
/*
    if (glue_isMyself(json_manufacture->valuestring, json_manufactureSN->valuestring) == 0)
    {
        iotc_error("got MSG_DEV_ONLINE_RSP not for myself! %s-%s",
                json_manufacture->valuestring, 
                json_manufactureSN->valuestring);
        return -1;
    }
*/

    glue_updateDevId(json_deviceId->valueint, json_zburl->valuestring);
/*
    if (iotcSess_gotRsp(MSG_DEV_ONLINE_RSP, json_cmdId->valueint) != 1)
    {
        iotc_error("got unexpected MSG_DEV_ONLINE_RSP, cmdId=%d", json_cmdId->valueint);
        return -1;
    }
*/
/*
    iotc_sendDevBwInfoMsg();
*/
    iotc_debug("Exit.");
    return 0;
}

static int handle_set(cJSON *json)
{
    cJSON *json_deviceId=NULL, *json_devData=NULL;

    iotc_debug("Enter.");

    json_deviceId = cJSON_GetObjectItem(json, "deviceId");
    json_devData = cJSON_GetObjectItem(json, "devData");

    /* integrity and validity check */
    if(!json_deviceId || !json_devData)
    {
        iotc_error("missing json param!");
        return -1;
    }

    if (json_deviceId->type != cJSON_String ||
        json_devData->type != cJSON_Object )
    {
        iotc_error("param type is wrong!");
        return -1;
    }

    /* TODO: now always reply with success
     *       need add setting processing */
    glue_handleSet(json_devData);
    iotc_sendSetRspMsg(0/*json_cmdId->valueint cmdId*/, 0/*retCode*/, json_devData);

    iotc_debug("Exit.");
    return 0;
}


int iotc_parseHttpBody(char *buf)
{
    cJSON *json=NULL, *json_type=NULL;

    iotc_debug("Enter.");

    iotc_debug("len=%d \r\nbuf=%s", strlen(buf), buf);

    /* parse json_buf */
    if ((json=cJSON_Parse(buf)) == NULL)
    {
        //iotc_error("json parse http body failed! %s\n", cJSON_GetErrorPtr());
        iotc_error("json parse http body failed!\n");
        return -1;
    }

    /* parse item "type" */ 
    if ((json_type=cJSON_GetObjectItem(json, "type")) == NULL)
    {
        iotc_error("type is missing!");
        cJSON_Delete(json);  
        return -1;
    }

    if (json_type->type != cJSON_Number)
    {
        iotc_error("type's value is missing or in wrong format!");
        cJSON_Delete(json);
        return -1;
    }

    iotc_debug("type=%d", json_type->valueint);
    switch(json_type->valueint)
    {
        case MSG_DEV_ONLINE_RSP:
            handle_devOnlineRsp(json);
            break;

        case MSG_ZB_GET_LIST:
            //handle_set(json);
            break;

        defalut:
            iotc_error("Can not find msgType for %d\r\n", json_type->valueint);
            break;
    }

    /* free */
    cJSON_Delete(json);

    iotc_debug("Exit.");
    return 0;
}

int iotc_handleServerPkt(char *recvbuf)
{
    char *body = NULL;

    iotc_debug("Enter.");
    if (0 == iotc_parseHttpHeader(recvbuf))
    {
        if ((body=iotc_getHttpBody(recvbuf)) != NULL)
        {
            iotc_parseHttpBody(body);
        }
    }

    iotc_debug("Exit.");
    return 0;
}
