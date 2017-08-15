#ifndef __HTTP_H__
#define __HTTP_H__

#define MY_HTTP_DEFAULT_PORT 80

int get_resource_list(const char* path, const char* host);
int p2p_connect_setup(void);
int transmission_connect_setup(void);
void clear_resource_list(void);
int new_resource_report(int port);
int resource_down_report(void);
int new_connection_report(const char *src);
int connection_down_report(unsigned int totalBytes);
int init_in_parent_process(void);
#endif
