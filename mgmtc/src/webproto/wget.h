#ifndef _WGET_H_
#define _WGET_H_

#include "protocol.h"
//#include "../main/event.h"
//#include "cms_tmr.h"

/*----------------------------------------------------------------------*/
typedef enum
{
   iWgetStatus_Ok = 0,
   iWgetStatus_InternalError,
   iWgetStatus_ConnectionError,
   iWgetStatus_Error,
   iWgetStatus_HttpError
} tWgetStatus;

typedef struct
{
   tWgetStatus status;
   tProtoCtx   *pc;
   tHttpHdrs   *hdrs;
   const char  *msg;  /* Msg associated with status */
   void        *handle;
} tWget;

typedef enum
{
   eCloseConnection=0,
   eKeepConnectionOpen  /* used by wConnect and wClose */
} tConnState;

typedef enum
{
   eUndefined,
   eConnect,
   ePostData,
   eGetData,
   ePutData,
   eDisconnect
} tRequest;

typedef struct XtraPostHdr
{
   struct XtraPostHdr *next;
   char               *hdr;   /* header string */
   char               *value; /* value string*/
} XtraPostHdr;

typedef struct
{
   tConnState        keepConnection;
   int               status;
   tRequest          request;
   int               cbActive; /* set to 1 if callback from report status */
   tProtoCtx         *pc;
   CmsEventHandler   cb;
   void              *handle;
   char              *proto;
   char              *host;
   tIpAddr           host_addr;
   int               port;
   char              *uri;
   tHttpHdrs         *hdrs;
   CookieHdr         *cookieHdrs;
   XtraPostHdr       *xtraPostHdrs;
   char              *content_type;
   char              *postdata;
   int               datalen;
} tWgetInternal;

/*----------------------------------------------------------------------*
 * returns
 *   0 if sending request succeded
 *  -1 on URL syntax error
 *
 * The argument to the callback is of type (tWget *)
 */
tWgetInternal *wget_Connect(const char *url, CmsEventHandler callback, void *handle);
tWgetInternal *wget_isConnected(tWgetInternal  *wg, CmsEventHandler callback, void *handle); //Add by hangxu 2014/9/3
int wget_GetData(tWgetInternal *wg, CmsEventHandler callback, void *handle);
int wget_PostData(tWgetInternal *,char *data, int datalen, char *contenttype,
                  CmsEventHandler callback, void *handle);
int wget_PostDataClose(tWgetInternal *,char *data, int datalen, char *contenttype,
                       CmsEventHandler callback, void *handle);
int wget_PutData(tWgetInternal *,char *data, int datalen, char *contenttype, CmsEventHandler callback, void *handle);
int wget_Disconnect(tWgetInternal *);
const char *wget_LastErrorMsg(void);
int wget_AddPostHdr(tWgetInternal *wio, char *xhdrname, char *value);
void wget_ClearPostHdrs(tWgetInternal *wio);
#endif

