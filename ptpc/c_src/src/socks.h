#ifndef __SOCKS_H__
#define __SOCKS_H__

#define FLV_SRV_PORT 9999
#define FLV_SERVER_ADDR  "/var/flv_server"
#define FLV_MESSAGE_BACKLOG 3


int initUnixDomainServerSocket(char *path);
int connect_to_master(char *path);

int init_flv_server(int *server_port);
#endif
