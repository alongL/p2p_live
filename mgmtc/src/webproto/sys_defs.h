#ifndef __SYS_DEFS_H__
#define __SYS_DEFS_H__

#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "../iotc_log.h"


#define MSECS_IN_SEC (1000)
#define TRUE    1
#define FALSE   0

typedef unsigned int tIpAddr;
#ifndef BOLL_TYPE_ALREADY_DEFINED
#define BOLL_TYPE_ALREADY_DEFINED
typedef uint8_t UBOOL8;
#endif
typedef unsigned int UINT32;

typedef void (*CmsEventHandler)(void*);

#define cmsLog_error iotc_error
#define cmsLog_debug iotc_debug
#define cmsLog_notice iotc_debug

static inline void stopListener(int fd)
{
}

static inline void cmsMem_free(void *p)
{
    if(p==NULL)
    {
        return;
    }

    free(p);
}

static inline char* cmsMem_strdup(const char *str)
{
    unsigned int len;
    void *buf;

    if (str == NULL)
    {
        return NULL;
    }

    len = strlen(str);
    buf = malloc(len+1);

    if (buf == NULL)
    {
        return NULL;
    }

    strncpy((char*)buf, str, len+1);
    return ((char*)buf);
}
#endif
