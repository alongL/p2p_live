#ifndef __SOCKS_H__
#define __SOCKS_H__

#define FLV_SRV_PORT 9999
#define FLV_SERVER_ADDR  "/var/flv_server"
#define FLV_MESSAGE_BACKLOG 3

#define MSG_NEW_RESOUCE     1
#define MSG_GET_RESOURCE    0
#define MSG_RESOUCE_DOWN    2
#define MSG_NEW_CONN        3
#define MSG_CONN_DOWN       4
#define DEV_ID_LEN          128
#define ZB_SRV_URL_LEN      128
#define RESID_LEN           64
#define SERVICE_URL_LEN     256

int initUnixDomainServerSocket(char *path);
int connect_to_master(char *path, int port);

int init_flv_server(int *server_port);
#endif
