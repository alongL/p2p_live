#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/time.h>
#include "iotc_log.h"

int iotc_log_level_int = LOG_LEVEL_DEBUG ;
void log_log(LOG_LEVEL log_level, const char *func, unsigned int line_num, const char *p_fmt, ... )
{
    char *log_level_ch_ptr=NULL;
    int len=0;
    char buf[MAX_LOG_LINE_LENGTH]={0};
    va_list      ap;
    struct timeval tv;

    gettimeofday(&tv, NULL);

    switch(log_level)
    {
        case LOG_LEVEL_ERR:
            log_level_ch_ptr = "[Error]";
            break;

        case LOG_LEVEL_DEBUG:
            log_level_ch_ptr = "[Debug]";
            break;

        default:
            log_level_ch_ptr = "[Unknown]";
    }

    len=snprintf(buf, MAX_LOG_LINE_LENGTH-1, "%s %u.%u %s[%d] ", log_level_ch_ptr, 
            (unsigned int)tv.tv_sec, (unsigned int)tv.tv_usec, func, line_num);

    if ( log_level <= iotc_log_level_int)
    {
        int log_fd = open("/dev/console",  O_RDWR);

        if ( -1 != log_fd)
        {
            va_start(ap, p_fmt);
            vsnprintf(&(buf[strlen(buf)]), MAX_LOG_LINE_LENGTH-len-1, p_fmt, ap);
            write(log_fd, buf, strlen(buf));
            write(log_fd, "\n", strlen("\n"));
            va_end(ap);
            close(log_fd);
        }
    }

    return;
}
