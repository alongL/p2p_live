#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <libubox/uloop.h>
#include "iotc.h"

typedef struct WaitRspItem {
    AgentMsgType msgType;
    unsigned int cmdId;
    int count;
    struct WaitRspItem *next;
} WaitRspItem;

static WaitRspItem *g_head=NULL;
static WaitRspItem *g_tail=NULL;


static int iotcSess_startWaitRspTimer();

static void iotcSess_checkRspTimeout()
{
    WaitRspItem *node=g_head;
    int toRspNum=0;
    int toDevOnlineRspNum=0;

    while(node)
    {
        if (node->count > 0)
        {
            toRspNum++;
            if (node->msgType == MSG_DEV_ONLINE_RSP)
            {
                toDevOnlineRspNum++;
            }
        }

        node = node->next;
        iotc_error("%s[%d] while node",__FUNCTION__,__LINE__);
    }

    if (toDevOnlineRspNum>0)
    {
        /* TODO: need do something */
        iotc_error("missing response for %d device online msg", toDevOnlineRspNum);
    }

    if (g_head != NULL)
    {
        iotcSess_startWaitRspTimer();
    }
}

struct uloop_timeout g_waitRspTm= {
    .cb = iotcSess_checkRspTimeout,
};

static int iotcSess_startWaitRspTimer()
{
    uloop_timeout_set(&g_waitRspTm, 2000);
}

int iotcSess_waitRsp(AgentMsgType msgType, unsigned int cmdId)
{
    WaitRspItem *newNode=NULL;

    if ((newNode=malloc(sizeof(WaitRspItem))) == NULL)
    {
        return -1;
    }

    newNode->msgType=msgType;
    newNode->cmdId=cmdId;
    newNode->count=0;
    newNode->next=NULL;

    if (g_head==NULL)
    {
        g_head=newNode;
        g_tail=newNode;
    }
    else
    {
        g_tail->next=newNode;
        g_tail=newNode;
    }

    iotcSess_startWaitRspTimer();

    return 0;
}

int iotcSess_gotRsp(AgentMsgType msgType, unsigned int cmdId)
{
    WaitRspItem *node=g_head, *node_pre=g_head;

    while(node)
    {
        if (node->msgType==msgType && node->cmdId==cmdId)
        {
            if (node==g_head)
            {
                g_head=node->next;
                if (node==g_tail)
                {
                    g_tail=NULL;
                }
            }
            else if (node==g_tail)
            {
                node_pre->next=NULL;
                g_tail=node_pre;
            }
            else
            {
                node_pre->next=node->next;
            }

            free(node);
            return 1;
        }
        node_pre=node;
        node=node->next;
    }

    return 0;
}
