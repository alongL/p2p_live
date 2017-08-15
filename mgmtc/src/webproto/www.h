/***********************************************************************
 *
 *  Copyright (c) 2005-2010  Broadcom Corporation
 *  All Rights Reserved
 *
 *
************************************************************************/

#ifndef _WWW_H_
#define _WWW_H_

//#include "cms_log.h"

/*----------------------------------------------------------------------*
 * Utility Library for web related stuff
 *----------------------------------------------------------------------*/
extern void www_StripTail(char *s);
extern void www_UrlDecode(char *s);
extern void www_UrlEncode(const char *s, char *t);

/*----------------------------------------------------------------------*
 * parse url on form:
 *  "<proto>://<host>[:<port>][<uri>]"
 *  returns
 *    0 if parse ok
 *   -1 if parse failed
 *  port sets to 0 if no port is specified in URL
 *  uri is set to "" if no URI is specified
 */
extern int www_ParseUrl(const char *url, char *proto, char *host, int *port, char *uri);
extern int www_EstablishConnection(tIpAddr host_addr, int port, int *sock_fd);

/* defined in httpDownload.c */
//extern char connIfName[CMS_IFNAME_LENGTH];
#endif
