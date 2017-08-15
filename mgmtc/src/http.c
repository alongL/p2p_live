#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include "iotc.h"


#define BUFFER_SIZE 1024
#define MY_HTTP_DEFAULT_PORT 80


#define HTTP_POST "POST /%s HTTP/1.1\r\nHost: %s:%d\r\nAccept: */*\r\n"\
    "Content-Type:application/json;charset=UTF-8\r\nContent-Length: %d\r\n\r\n%s"
#define HTTP_GET "GET %s HTTP/1.1\r\nHost: %s:%d\r\nAccept: */*\r\n\r\n"


int opensock (const char *host, int port, const char *bind_to)
{
    int sockfd, n;
    struct addrinfo hints, *res, *ressave;
    char portstr[6];

    //assert (host != NULL);
    //assert (port > 0);

    memset (&hints, 0, sizeof (struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    snprintf (portstr, sizeof (portstr), "%d", port);

    n = getaddrinfo (host, portstr, &hints, &res);
    if (n != 0) {
        iotc_debug ( "opensock: Could not retrieve info for %s", host);
        return -1;
    }

    ressave = res;
    do {
        sockfd = socket (res->ai_family, res->ai_socktype, res->ai_protocol);
        if (sockfd < 0)
            continue;       /* ignore this one */
#if 0
        /* Bind to the specified address */
        if (bind_to) {
            if (bind_socket (sockfd, bind_to) < 0) {
                close (sockfd);
                continue;       /* can't bind, so try again */
            }
        } else if (config.bind_address) {
            if (bind_socket (sockfd, config.bind_address) < 0) {
                close (sockfd);
                continue;       /* can't bind, so try again */
            }
        }
#endif
        if (connect (sockfd, res->ai_addr, res->ai_addrlen) == 0)
            break;  /* success */

        close (sockfd);
    } while ((res = res->ai_next) != NULL);

    freeaddrinfo (ressave);
    if (res == NULL) {
        iotc_debug ( "opensock: Could not establish a connection to %s", host);
        return -1;
    }

    return sockfd;
}


static int http_parse_url(const char *url,char *host,char *file,int *port)
{
    char *ptr1,*ptr2;
    int len = 0;
    if(!url || !host || !file || !port){
        return -1;
    }

    ptr1 = (char *)url;

    if(!strncmp(ptr1,"http://",strlen("http://"))){
        ptr1 += strlen("http://");
    }else{
        return -1;
    }

    ptr2 = strchr(ptr1,'/');
    if(ptr2){
        len = strlen(ptr1) - strlen(ptr2);
        memcpy(host,ptr1,len);
        host[len] = '\0';
        if(*(ptr2 + 1)){
            memcpy(file,ptr2 + 1,strlen(ptr2) - 1 );
            file[strlen(ptr2) - 1] = '\0';
        }
    }else{
        memcpy(host,ptr1,strlen(ptr1));
        host[strlen(ptr1)] = '\0';
    }
    /*get host and ip*/
    ptr1 = strchr(host,':');
    if(ptr1){
        *ptr1++ = '\0';
        *port = atoi(ptr1);
    }else{
        *port = MY_HTTP_DEFAULT_PORT;
    }

    return 0;
}


static int http_tcpclient_create(const char *host, int port)
{
    int socket_fd;

    socket_fd = opensock (host, port, NULL);
    if (socket_fd > 0) {
        iotc_debug ( "connected to %s:%d fd=%d ", host, port, socket_fd);
    } else {
        iotc_debug ( "connect to %s:%d failed!", host, port);
        close(socket_fd);
    }

    return socket_fd;
}

static void http_tcpclient_close(int socket)
{
    close(socket);
}


static int http_tcpclient_recv(int fd, char *lpbuff)
{
    int recvnum=0;
    char *l_ptr=NULL, *ptr=NULL;
    char contlenstr[16]={0};
    int len=0, cont_len=-1, head_len=-1, tot_len=-1;

    len = recv(fd, lpbuff, BUFFER_SIZE*4, 0);
    if (len < 0) {
        iotc_debug ( "%s %d: recv resp error %s", __FUNCTION__, __LINE__, strerror(errno));
        return len;
    }
    recvnum += len;
    lpbuff[recvnum] = 0;
    
    ptr = (char*)strstr(lpbuff,"\r\n\r\n");
    if (!ptr) {
        iotc_debug ( "%s %d: not found end of http head", __FUNCTION__, __LINE__);
        return 0;
    }

    head_len = ptr - lpbuff + 4;

    l_ptr = strstr(lpbuff, "Content-Length:");
    if (!l_ptr) {
        iotc_debug ( "%s %d: not found Content-Length", __FUNCTION__, __LINE__);
        return 0;
    }

    ptr = l_ptr + strlen("Content-Length:");
    while(*ptr == ' ') {
        ptr++;
    }
    l_ptr = ptr;

    while(*ptr) {
        if(*ptr == '\r') {
            if (ptr-l_ptr > 15) {
                iotc_debug ( "%s %d: Content-Length parse error!", __FUNCTION__, __LINE__, ptr-l_ptr);
                return -1;
            }
            memcpy(contlenstr, l_ptr, ptr-l_ptr);
            contlenstr[ptr-l_ptr] = '\0';
            cont_len = atoi(contlenstr);
            break;
        }
        ptr++;
    }

    if (cont_len < 0) {
        iotc_debug ( "%s %d: content length %d is error!", __FUNCTION__, __LINE__, cont_len);
        return 0;
    }

    tot_len = head_len + cont_len;
    while(recvnum < tot_len) {
        len = recv(fd, lpbuff+recvnum, BUFFER_SIZE*4-(tot_len-recvnum), 0);
        if(len < 0) {
            iotc_debug ( "%s %d: %s lpbuff=%s", __FUNCTION__, __LINE__, strerror(errno), lpbuff);
            return 0;
        }
        recvnum += len;
    }

    lpbuff[recvnum] = 0;
    return recvnum;
}

static int http_tcpclient_send(int socket,char *buff,int size)
{
    int sent=0, tmpres=0;

    while(sent < size) {
        tmpres = send(socket, buff+sent, size-sent, 0);
        if (tmpres == -1) {
            return -1;
        }
        sent += tmpres;
    }
    return sent;
}

static char *http_parse_result(const char *lpbuf)
{
    char *ptmp = NULL;
    char *response = NULL;

    ptmp = (char*)strstr(lpbuf,"HTTP/1.1");
    if (!ptmp) {
        iotc_debug( "http/1.1 not faind\n");
        return NULL;
    }

    if (atoi(ptmp + 9)!=200) {
        iotc_debug( "result:\n%s\n",lpbuf);
        return NULL;
    }

    ptmp = (char*)strstr(lpbuf,"\r\n\r\n");
    if (!ptmp) {
        iotc_debug( "ptmp is NULL\n");
        return NULL;
    }
    response = (char *)malloc(strlen(ptmp)+1);
    if (!response) {
        iotc_debug( "malloc failed \n");
        return NULL;
    }
    strcpy(response,ptmp+4);
    return response;
}

char* http_post(const char *url, const char *post_str)
{
    char lpbuf[BUFFER_SIZE*4]={0};
    char host_addr[BUFFER_SIZE]={0};
    char file[BUFFER_SIZE]={0};
    int fd=-1;
    int port=0;
    struct timeval tv;

    tv.tv_sec = 0;
    tv.tv_usec = 500000;

    if (!url || !post_str) {
        iotc_debug( "failed!\n");
        return NULL;
    }

    if (http_parse_url(url, host_addr, file, &port)) {
        iotc_debug( "http_parse_url failed!\n");
        return NULL;
    }

    fd = http_tcpclient_create(host_addr, port);
    if (fd < 0){
        iotc_debug( "http_tcpclient_create failed\n");
        return NULL;
    }

    sprintf(lpbuf, HTTP_POST, file, host_addr, port, strlen(post_str), post_str);

    if (http_tcpclient_send(fd, lpbuf, strlen(lpbuf)) < 0) {
        iotc_debug( "http_tcpclient_send failed..\n");
        return NULL;
    }

    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(struct timeval));

    /*it's time to recv from server*/
    memset(lpbuf, 0, sizeof(lpbuf));
    if (http_tcpclient_recv(fd, lpbuf) <= 0) {
        iotc_debug( "http_tcpclient_recv failed\n");
        return NULL;
    }

    http_tcpclient_close(fd);

    return http_parse_result(lpbuf);
}


int parse_response(char *string)
{
    char *ptr=NULL, *r_ptr=NULL;
    char ret_str[8]={0};

    ptr = strstr(string, "\"ret\":");
    if (!ptr) {
        return -1;
    }

    ptr += 6;
    while(*ptr==' ') {
        ptr++;
    }

    r_ptr = ptr;

    while(*ptr){
        if(*ptr==','||*ptr=='}') {
            if(ptr-r_ptr>7){
                return -1;
            }
            memcpy(ret_str, r_ptr, ptr-r_ptr);
            ret_str[ptr-r_ptr]='\0';
            return atoi(ret_str);
        }
        ptr++;
    }

    return -1;
}


