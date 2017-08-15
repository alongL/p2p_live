#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include "iotc.h"

uint32_t g_devId;
char    g_zburl[64];
char g_manufacture[32]={0};
char g_manufactureSN[64]={0};
extern char iotc_wan_ip[MAX_IP_LEN];
extern bool isPublicIp;

int glue_init()
{
    FILE *fp;
    char *ptr;
    char mac[16],line[128],macs[32];

    memset(line,0,sizeof(line));
    memset(mac,0,sizeof(mac));
    memset(macs,0,sizeof(macs));
    system("ifconfig eth0 > /var/eth0mac");

    if ((fp=fopen("/var/eth0mac","r"))==NULL){
        printf("fopen error\n");
        return NULL;
    }
    fgets(line,sizeof(line),fp);
    fclose(fp);

    ptr = strstr(line, "HWaddr");
    while(*ptr++ != ' ')
        ;
    strcpy(macs,ptr);

    mac[0] = macs[0];
    mac[1] = macs[1];
    mac[2] = macs[3];
    mac[3] = macs[4];
    mac[4] = macs[6];
    mac[5] = macs[7];
    mac[6] = macs[9];
    mac[7] = macs[10];
    mac[8] = macs[12];
    mac[9] = macs[13];
    mac[10] = macs[15];
    mac[11] = macs[16];

    strcpy(g_manufacture, "Phicomm");
    strcpy(g_manufactureSN, mac);

    return 0;
}
/*
char* glue_getDevData()
{
    return g_devData;
}

int glue_isMyself(char *manufacture, char *manufactureSN)
{
    if (manufacture == NULL || manufactureSN == NULL)
    {
        return 0;
    }

    if (strcmp(manufacture, g_manufacture))
    {
        return 0;
    }
    
    if (strcmp(manufactureSN, g_manufactureSN))
    {
        return 0;
    }

    return 1;
}
*/
void glue_updateDevId(uint32_t devId, char *zburl)
{
    char cmd[256];

    if (zburl)
    {
        strcpy(g_zburl,zburl);
        
        g_devId = devId;
        memset(cmd, 0, sizeof(cmd));
        sprintf(cmd,"echo %d > /var/deviceid", g_devId);
        system(cmd);
        iotc_error("cmd:%s",cmd);

        memset(cmd, 0, sizeof(cmd));
        sprintf(cmd,"echo %s > /var/zburl", zburl);
        system(cmd);
        iotc_error("cmd:%s",cmd);

        memset(cmd, 0, sizeof(cmd));
        sprintf(cmd,"/etc/init.d/tinyproxy restart");
        system(cmd);
        iotc_error("cmd:%s",cmd);
    }
    else
    {
        iotc_error("devId is NULL");
    }
}

int sendSignalToTuya(char *signal)
{
    int pid=0;
    int i=0;
    FILE *fp=NULL;
    char c, line[256]={0}, cmd[128]={0};

    iotc_debug("Enter.");

    if ((fp=fopen("/var/tuyaled_pid", "r")) == NULL)
    {
        iotc_error("missing /var/tuyaled_pid!");
        return -1;
    }

    if (!fgets(line, sizeof(line), fp))
    {
        iotc_error("read /var/tuyaled_pid failed! %s", strerror(errno));
        close(fp);
        return -1;
    }
    close(fp);

    for(i=0; i<10; i++)
    {
        c=line[i];
        if (c >= '0' && c <= '9')
        {
            pid = pid*10 + c - '0';
        }
        else if (c == '\r' || c == '\n')
        {
            break;
        }
        else
        {
            iotc_error("content of /var/tuyaled_pid is wrong! %s", line);
            return -1;
        }
    }

    if (pid < 1)
    {
        iotc_error("get pid of tuyaled_a failed!");
        return -1;
    }

    sprintf(cmd, "kill -%s %d&", signal, pid);
    iotc_debug("#. cmd=%s", cmd);
    system(cmd);

    iotc_debug("Enter.");
    return 0;
}

int glue_handleSet(cJSON *json)
{
    int ret=-1;
    cJSON *json_power=NULL, *json_color=NULL;

    iotc_debug("Enter.");

    json_power = cJSON_GetObjectItem(json, "power");
    json_color = cJSON_GetObjectItem(json, "color");

    if (!json_power && !json_color)
    {
        iotc_error("missing param wantint to be set!");
        return -1;
    }


    iotc_debug("Enter.");
    if (json_power && json_power->type == cJSON_String)
    {
    iotc_debug("Enter.");
        if (!json_power->valuestring)
        {
            iotc_error("value of power is missing!");
            return -1;
        }

        if (strcmp(json_power->valuestring, "1") == 0)
        {
            system("echo 1 > /var/led_power &");
        }
        else if (strcmp(json_power->valuestring, "0") == 0)
        {
            system("echo 0 > /var/led_power &");
        }
        else
        {
            iotc_error("value of power %s is out of range!", json_power->valuestring);
            return -1;
        }

        if (sendSignalToTuya("SIGUSR1") == -1)
        {
            iotc_error("send cmd to device failed!");
            return -1;
        }

    iotc_debug("Enter.");
        ret=0;
    }
    iotc_debug("Enter.");

    if (json_color && json_color->type == cJSON_String)
    {
        char cmd[256]={0};

        /* need check validation of color's value */
        snprintf(cmd, 255, "echo %s > /var/led_color", json_color->valuestring);
        system(cmd);

        if (sendSignalToTuya("SIGUSR2") == -1)
        {
            iotc_error("send cmd to device failed!");
            return -1;
        }

        ret=0;
    }

    iotc_debug("Exit.");

    return ret;
}

