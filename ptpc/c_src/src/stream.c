#include "main.h"
#include "heap.h"
#include "log.h"
#include "stream.h"
#include <sys/mman.h>

extern int allow_debug;
#define ALLOW_DEBUG if(allow_debug == 1) {log_message (LOG_INFO, "------%s %d", __FUNCTION__, __LINE__);}

struct stream_s *g_flv=NULL;
struct stream_s *g_dbg_st=NULL;

void set_dbg_st_ptr(struct stream_s *ptr)
{
    g_dbg_st=ptr;
}

#ifdef TAG_STREAM_DEBUG
struct ts_debug_s {
    struct dataNode *head;
    struct dataNode *tail;
    unsigned int alloc;
    unsigned int free;
};

struct ts_debug_s ts_debug;

void add_to_ts_debug(struct dataNode *node)
{
    if (ts_debug.head == NULL) {
        ts_debug.head = node;
        ts_debug.tail = node;
    } else {
        ts_debug.tail->next = node;
        ts_debug.tail = node;
    }
    ts_debug.alloc++;
}

void rm_from_ts_debug(struct dataNode *node)
{
    struct dataNode *temp=NULL;
    
    if (ts_debug.head == node && ts_debug.tail == node) {
        ts_debug.head = NULL;
        ts_debug.tail = NULL;
        ts_debug.free++;
        return;
    }

    if (ts_debug.head == node) {
        ts_debug.head = node->next;
        ts_debug.free++;
        return;
    }

    temp=ts_debug.head;

    while(temp) {
        if (temp->next == node) {
            if (ts_debug.tail == node) {
                ts_debug.tail = temp;
            }
            temp->next=node->next;
            ts_debug.free++;
            return;
        }
        temp = temp->next;
    }
}
#endif

void ts_debug_init(void)
{
#ifdef TAG_STREAM_DEBUG
    ts_debug.head = NULL;
    ts_debug.tail = NULL;
    ts_debug.alloc = 0;
    ts_debug.free = 0;
#endif
}

static void print_ts_debug(void)
{
#ifdef TAG_STREAM_DEBUG
    struct dataNode *node=ts_debug.head;
    while(node) {
        log_message (LOG_CONN, "node:%p refCnt:%d", node, node->refCnt);
        node = node->next;
    }
#endif
}

void print_stream_info (struct stream_s * streamptr)
{
    struct flvtag_s *tag;

    assert (streamptr != NULL);

#ifdef TAG_STREAM_DEBUG
    log_message (LOG_INFO, "======stream=%p, size=%d, in=%d, out=%d alloc=%d free=%d", 
            streamptr, streamptr->size, streamptr->in_size, streamptr->out_size,
            ts_debug.alloc, ts_debug.free); 
#else
    log_message (LOG_INFO, "======stream=%p, size=%u, in=%u, out=%u ts_delta=%u", 
            streamptr, streamptr->size, streamptr->in_size, streamptr->out_size, streamptr->ts_delta);
#endif
    print_ts_debug();

    if (streamptr->size == 0)
        return;

    tag = LIST_HEAD (streamptr);

    if(tag) {
        while(tag) {
            log_message (LOG_INFO, "======tag=%p, refCnt=%d", tag, tag->data->refCnt); 
            tag = tag->next;
        }
    }
    return;
}

static struct flvtag_s *makenewtag (struct dataNode * data, size_t length)
{
    struct flvtag_s *newtag=NULL;
    unsigned char *hdr=NULL;
    unsigned char ts[4];


    assert (data != NULL);
    assert (length > 0);

    newtag = (struct flvtag_s *) safemalloc (sizeof (struct flvtag_s));
    if (!newtag)
        return NULL;

    hdr = data->string;

    newtag->data = data;
    ts[0] = *(hdr+11);
    ts[1] = *(hdr+8);
    ts[2] = *(hdr+9);
    ts[3] = *(hdr+10);
    if (*hdr == 0x08 || *hdr == 0x09) {
        newtag->time_stamp = ntohl(*((unsigned int*)&ts));
    } else {
        newtag->time_stamp = 0;
    }
    newtag->length = length;
    newtag->pos = 0;
    newtag->next = NULL;

    return newtag;
}

/*
 * Free the allocated tag
 */
static void free_tag (struct flvtag_s *tag)
{
    assert (tag != NULL);

    if (!tag)
        return;

    if (tag->data) {
        if (tag->data->refCnt == 0) {
#if 0
            log_message (LOG_INFO, "free tag data:tag=%p data=%p", tag, tag->data);
#endif
            safefree (tag->data);
        } else {
            if (tag->data->refCnt > 3) {
                log_message (LOG_INFO, "======refCnt=%d tag=%p", tag->data->refCnt, tag);
            }
        }
    }
    safefree (tag);
}

/*
 * Remove the first tag from the top of the stream 
 */
static struct flvtag_s *remove_from_stream (struct stream_s *streamptr)
{
    struct flvtag_s *tag;

    assert (streamptr != NULL);
    assert (LIST_HEAD (streamptr) != NULL);

    tag = LIST_HEAD (streamptr);
    LIST_HEAD (streamptr) = tag->next;

    if (LIST_HEAD (streamptr) == NULL) {
        LIST_TAIL (streamptr) = NULL;
    }

    streamptr->size -= (tag->length-tag->pos);
    streamptr->out_size += (tag->length-tag->pos);
    tag->data->refCnt--;
#ifdef DEBUG_TAG_STATS
    log_message (LOG_INFO, "remove stream head: old=%p new=%p", tag, tag->next);
#endif

    return tag;
}

/*
 * Push a new tag on to the end of the buffer.
 */
int add_to_stream (struct stream_s *streamptr, struct dataNode *data, size_t length)
{
    struct flvtag_s *newtag;

    assert (streamptr != NULL);
    assert (data != NULL);

    /*
     * Sanity check here. A buffer with a non-NULL head pointer must
     * have a size greater than zero, and vice-versa.
     */
    if (LIST_HEAD (streamptr) == NULL)
        assert (streamptr->size == 0);
    else
        assert (streamptr->size > 0);

    /*
     * Make a new line so we can add it to the buffer.
     */
    if (!(newtag = makenewtag (data, length)))
        return -1;

    if (LIST_TAIL (streamptr) == NULL)
        LIST_HEAD (streamptr) = LIST_TAIL (streamptr) = newtag;
    else {
        LIST_TAIL (streamptr)->next = newtag;
        LIST_TAIL (streamptr) = newtag;
    }

    /* record pre tag's during time before current tag */
    *((unsigned int *)data->string) = htonl(newtag->time_stamp - streamptr->last_recv_ts);
    streamptr->last_recv_ts = newtag->time_stamp;
    streamptr->size += length;
    streamptr->in_size += length;
    newtag->data->refCnt++;

#ifdef DEBUG_TAG_STATS
    log_message (LOG_INFO, "recv0: tag=%p tag(%d:%d) data(%d:%d) stream_size=%d", newtag,
            newtag->pos, newtag->length, newtag->data->len, newtag->data->tagLen, streamptr->size);
#endif

    return 0;
}

/*
 * Return the current size of the stream.
 */
size_t stream_size (struct stream_s *streamptr)
{
    return streamptr->size;
}

struct stream_s *new_stream(void)
{
    struct stream_s *streamptr;

    streamptr = (struct stream_s *) safemalloc (sizeof (struct stream_s));
    if (!streamptr)
        return NULL;

    memset(streamptr, 0, sizeof(struct stream_s));

    return streamptr;
}

void delete_stream (struct stream_s *streamptr)
{
    struct flvtag_s *next;

    if (!streamptr) {
        return;
    }

    while (LIST_HEAD (streamptr)) {
        next = LIST_HEAD (streamptr)->next;
        LIST_HEAD (streamptr)->data->refCnt--;
        free_tag (LIST_HEAD (streamptr));
        LIST_HEAD (streamptr) = next;
    }

    safefree (streamptr);
}

void record_pre_tags(struct stream_s *streamptr)
{
    struct flvtag_s *newtag;
    struct flvtag_s *oritag;
    /* unsigned char *ptr; */

    /* time stamp should not be larger than 0 */
    if (streamptr->tag_hdr[8] != 0 ||
            streamptr->tag_hdr[9] != 0 || 
            streamptr->tag_hdr[10] != 0 ||
            streamptr->tag_hdr[11] != 0) {
        return;
    }

    if ( (streamptr->tag_hdr[4] == 0x08 && streamptr->tag_flag & 0x1) || 
            (streamptr->tag_hdr[4] == 0x09 && streamptr->tag_flag & 0x2)) {
        return;
    }

    /* ptr = streamptr->tag_hdr; */

    oritag = LIST_TAIL(streamptr);

    if (streamptr->pre_tags_tail == NULL) {
        struct dataNode *data;
        data = (struct dataNode *)safemalloc(FLV_HDR_LEN_EXT+oritag->data->tagLen+(size_t)&(((struct dataNode *)0)->string));
        memcpy(data->string, streamptr->hdr, FLV_HDR_LEN_EXT);
        data->refCnt = 0;
        data->tagLen = oritag->data->tagLen + FLV_HDR_LEN_EXT;
        data->len = data->tagLen;

        if (!(newtag = makenewtag (data, data->len))) {
            log_message (LOG_ERR, "%s %d: makenewtag failed!", __FUNCTION__, __LINE__);
            return;
        }
        memcpy(data->string+FLV_HDR_LEN_EXT, oritag->data->string, oritag->data->tagLen);

        streamptr->pre_tags_head = streamptr->pre_tags_tail = newtag;
    } else {
        if (!(newtag = makenewtag (oritag->data, oritag->length))) {
            log_message (LOG_ERR, "%s %d: makenewtag failed!", __FUNCTION__, __LINE__);
            return;
        }
        streamptr->pre_tags_tail->next = newtag;
        streamptr->pre_tags_tail = newtag;
    }
    newtag->data->refCnt++;

    if (streamptr->tag_hdr[0] == 0x08) {
        streamptr->tag_flag |= 0x1;
    } else if (streamptr->tag_hdr[0] == 0x09) {
        streamptr->tag_flag |= 0x2;
    }
}

static int recv_error_handle(int fd)
{
    switch (errno) {
#ifdef EWOULDBLOCK
        case EWOULDBLOCK:
#else
#  ifdef EAGAIN
        case EAGAIN:
#  endif
#endif
        case EINTR:
            return 0;
        default:
            log_message (LOG_ERR, "recv() error \"%s\" on fd %d", strerror (errno), fd);
            return -1;
    }
}
/*
 * Reads the bytes from the socket, and adds them to the buffer.
 * Takes a connection and returns the number of bytes read.
 */
#define READ_BUFFER_SIZE (1024 * 2)
ssize_t read_flv_stream (int fd, struct stream_s *streamptr, int isP2P)
{
    ssize_t bytesin=0;
    unsigned int flv_hdr_len = FLV_HDR_LEN;
    unsigned int flv_tag_hdr_len = FLV_TAG_HDR_LEN;

    assert (fd >= 0);
    assert (streamptr != NULL);

    if (streamptr->size >= MAXBUFFSIZE)
        return 0;

    if (isP2P) {
        flv_hdr_len += 4;
        flv_tag_hdr_len += 4;
    }

    if (streamptr->recv_st == FLV_WAIT_HDR) {
        bytesin = read (fd, &streamptr->hdr[streamptr->curr_len], flv_hdr_len-streamptr->curr_len);
        if (bytesin==0) { /* connection was closed by client */
            return -2;
        } else if (bytesin < 0) {
            return recv_error_handle(fd);
        } else {
            if (bytesin + streamptr->curr_len == flv_hdr_len) {
                struct dataNode *data;
                streamptr->recv_st = FLV_WAIT_TAG_HDR;
                streamptr->curr_len = 0;
                data = (struct dataNode *)safemalloc(FLV_HDR_LEN_EXT+(size_t)&(((struct dataNode *)0)->string));
                if (data == NULL) {
                    log_message (LOG_ERR, "read flv stream: ENOMEM");
                    return -3;
                }
                if(isP2P) {
                    memcpy(data->string, streamptr->hdr, flv_hdr_len);
                } else {
                    memcpy(data->string+4, streamptr->hdr, flv_hdr_len);
                }
                data->refCnt = 0;
                data->tagLen = FLV_HDR_LEN_EXT;
                data->len = FLV_HDR_LEN_EXT;
                if (add_to_stream(streamptr, data, FLV_HDR_LEN_EXT) < 0) {
                    safefree(data);
                    log_message (LOG_ERR, "can not add data to stream!");
                    return -4;
                }
            } else {
                streamptr->curr_len += bytesin;
            }
        }
    }
    
    if (streamptr->recv_st == FLV_WAIT_TAG_HDR) {
        bytesin = read(fd, &streamptr->tag_hdr[streamptr->curr_len], flv_tag_hdr_len-streamptr->curr_len);
        if (bytesin==0) { /* connection was closed by client */
            return -2;
        } else if (bytesin < 0) {
            return recv_error_handle(fd);
        } else {
            if (bytesin + streamptr->curr_len == flv_tag_hdr_len) {
                int tag_len=0;
                struct dataNode *data;

                streamptr->recv_st = FLV_WAIT_TAG_END;
                tag_len = FLV_TAG_HDR_LEN_EXT + streamptr->tag_hdr[1]*0x10000+streamptr->tag_hdr[2]*0x100+streamptr->tag_hdr[3]+4;
                data = (struct dataNode *)safemalloc(tag_len+(size_t)&(((struct dataNode *)0)->string));
                if (data == NULL) {
                    log_message (LOG_ERR, "read flv stream: ENOMEM");
                    return -3;
                }
                if (isP2P) {
                    memcpy(data->string, streamptr->tag_hdr, flv_tag_hdr_len);
                } else {
                    memcpy(data->string+4, streamptr->tag_hdr, flv_tag_hdr_len);
                }
                data->refCnt = 0;
                data->tagLen = tag_len;
                data->len = FLV_TAG_HDR_LEN_EXT;
                
#ifdef DEBUG_TAG_STATS
                {
                    unsigned char *ptr = streamptr->tag_hdr;
                    log_message (LOG_INFO, "TAG:%02x %02x %02x %02x %02x %02x %02x %02x", 
                            *ptr++, *ptr++, *ptr++, *ptr++, *ptr++, *ptr++, *ptr++, *ptr++);
                }
#endif
                if (add_to_stream(streamptr, data, FLV_TAG_HDR_LEN_EXT) < 0) {
                    safefree(data);
                    log_message (LOG_ERR, "can not add data to stream!");
                    return -4;
                }
            } else {
                streamptr->curr_len += bytesin;
            }
        }
    }

    if (streamptr->recv_st == FLV_WAIT_TAG_END) {
        struct flvtag_s *currtag;
        int max_read_size = 0;

        currtag = LIST_TAIL (streamptr);
        assert(currtag != NULL);

        max_read_size = currtag->data->tagLen - currtag->data->len;
        if (max_read_size > READ_BUFFER_SIZE) {
            max_read_size = READ_BUFFER_SIZE;
        }

        bytesin = read (fd, currtag->data->string+currtag->data->len, max_read_size);
        if (bytesin==0) { /* connection was closed by client */
            return -2;
        } else if (bytesin < 0) {
            return recv_error_handle(fd);
        } else {
            currtag->data->len += bytesin;
            currtag->length += bytesin;
            streamptr->size += bytesin;
            streamptr->in_size += bytesin;
            st_writeDataToPiece(streamptr, currtag, bytesin);
            if (currtag->data->len == currtag->data->tagLen) {
                streamptr->recv_st = FLV_WAIT_TAG_HDR;
                streamptr->curr_len = 0;
                record_pre_tags(streamptr);

#ifdef DEBUG_TAG_STATS
                log_message (LOG_INFO, "recv1: tag=%p tag(%d:%d) data(%d:%d) stream_size=%d", currtag,
                        currtag->pos, currtag->length, currtag->data->len, currtag->data->tagLen, streamptr->size);
#endif
            }
        }
    }

    return bytesin;
}

ssize_t write_flv_stream (int fd, struct stream_s * streamptr, int isP2P)
{
    ssize_t bytessent;
    struct flvtag_s *tag;
    ssize_t len;

    assert (fd >= 0);
    assert (streamptr != NULL);

    if (streamptr->size == 0) {
        return 0;
    }

    /* Sanity check. It would be bad to be using a NULL pointer! */
    assert (LIST_HEAD (streamptr) != NULL);
    tag = LIST_HEAD (streamptr);

    if (tag->pos == 0 && isP2P == 0) {
        tag->pos += 4;
        streamptr->size -= 4;
    }

    len = tag->length - tag->pos;

    if (tag->length < tag->pos) {
        log_message (LOG_ERR, "tag=%p pos=%d len=%d", tag, tag->pos, tag->length);
    }

    assert(len >= 0);

    if (len == 0) {
        return 0;
    }

#if 0
    if (g_dbg_st == streamptr) {
        unsigned char *ptr=tag->data->string;
        log_message (LOG_ERR, "tag(%p)=%02x %02x %02x %02x %02x %02x %02x %02x tag(%d:%d) data(%d:%d)", tag,
                *ptr++, *ptr++, *ptr++, *ptr++, *ptr++, *ptr++, *ptr++, *ptr++,
                tag->pos, tag->length, tag->data->len, tag->data->tagLen);
    }
#endif

    if (tag->pos == 0 && (tag->data->string[4] == 0x08 || tag->data->string[4] == 0x09)) {
        unsigned int ts_n = htonl(tag->time_stamp);
        unsigned char *ts = (unsigned char *)&ts_n;
#if 0
        log_message (LOG_ERR, "ts_delta=%d old_ts=%02x%02x%02x%02x", streamptr->ts_delta,
                tag->data->string[4],tag->data->string[5],tag->data->string[6],tag->data->string[7]);
#endif
        if (*((unsigned int *)&tag->data->string[8]) != 0) {
            tag->data->string[8] = ts[1];
            tag->data->string[9] = ts[2];
            tag->data->string[10] = ts[3];
            tag->data->string[11] = ts[0];
        }
#if 0
        log_message (LOG_ERR, "ts_delta=%d new_ts=%02x%02x%02x%02x", streamptr->ts_delta,
                tag->data->string[4],tag->data->string[5],tag->data->string[6],tag->data->string[7]);
#endif
    }

    if (len > MAX_SEND_LEN) {
        len = MAX_SEND_LEN;
    }
    
#if 0
    if (g_dbg_st == streamptr) {
        log_message (LOG_INFO, "send: tag=%p tag(%d:%d) data(%d:%d) stream_size=%d len=%d", tag,
                tag->pos, tag->length, tag->data->len, tag->data->tagLen, streamptr->size, len);
    }
#endif

    bytessent = send (fd, tag->data->string + tag->pos, len, MSG_NOSIGNAL);

    if (bytessent >= 0) { /* bytes sent, adjust buffer */
        tag->pos += bytessent;
        streamptr->size -= bytessent;
        streamptr->out_size += bytessent;
        if (tag->pos == tag->length && tag->length == tag->data->tagLen) {

#ifdef DEBUG_TAG_STATS
            log_message (LOG_INFO, "send: tag=%p tag(%d:%d) data(%d:%d) stream_size=%d", tag,
                    tag->pos, tag->length, tag->data->len, tag->data->tagLen, streamptr->size);
#endif
            free_tag (remove_from_stream(streamptr));
        }
        return bytessent;
    } else {
        switch (errno) {
#ifdef EWOULDBLOCK
            case EWOULDBLOCK:
#else
#  ifdef EAGAIN
            case EAGAIN:
#  endif
#endif
            case EINTR:
                return 0;
            case ENOBUFS:
            case ENOMEM:
                log_message (LOG_ERR, "write() error [NOBUFS/NOMEM] %s on fd %d", strerror (errno), fd);
                return 0;
            default:
                log_message (LOG_ERR, "write() error %s on fd %d tag=%p pos=%d len=%d", strerror(errno), fd, tag, tag->pos, tag->length);
                return -1;
        }
    }
}

int init_flv_recv_stream(void)
{
    g_flv = new_stream();
    if (!g_flv) {
        return -1;
    }

    return 0;
}

int clone_stream_data(struct stream_s *dst, struct stream_s *src)
{
    struct flvtag_s *oritag;
    struct flvtag_s *newtag;
    int len=0;

    assert (dst != NULL);
    assert (src != NULL);
    
    assert (LIST_TAIL (src) != NULL);
    oritag = LIST_TAIL(src);

    if (oritag->length == 0) {
        return 0;
    }

#if 0
    log_message (LOG_INFO, "%s: size=%d in_size=%d oritag(%d:%d) data(%p:%d:%d)",__FUNCTION__, 
            dst->size, dst->in_size, oritag->pos, oritag->length, oritag->data, oritag->data->len, oritag->data->tagLen);
#endif
    if (LIST_TAIL(dst) == NULL || LIST_TAIL(dst)->data != oritag->data) {
        if (!(newtag = makenewtag (oritag->data, oritag->length))) {
            return -1;
        }
        len = oritag->length;
        newtag->data->refCnt++;
        if (dst->ts_delta == 0) {
            dst->ts_delta = 0 - oritag->time_stamp;
            newtag->time_stamp = 0;
            log_message (LOG_INFO, "first tag's ts is %d", oritag->time_stamp);
        } else {
            newtag->time_stamp = oritag->time_stamp + dst->ts_delta;
        }
        if (dst->size == 0) {
            LIST_HEAD (dst) = LIST_TAIL (dst) = newtag;
        } else {
            LIST_TAIL (dst)->next = newtag;
            LIST_TAIL (dst) = newtag;
        }
    } else {
#if 0
        log_message (LOG_INFO, "%s: newtag(%d:%d) data(%p:%d:%d)", __FUNCTION__, LIST_TAIL(dst)->pos, LIST_TAIL(dst)->length,
                LIST_TAIL(dst)->data, LIST_TAIL(dst)->data->len, LIST_TAIL(dst)->data->tagLen);
#endif
        len = oritag->length - LIST_TAIL(dst)->length;
        LIST_TAIL(dst)->length = oritag->length;
    }

    dst->size += len;
    dst->in_size += len;

#if 0
    {
        struct flvtag_s *tag;
        tag = LIST_TAIL(dst);
        log_message (LOG_INFO, "%s: tag(%d:%d) data(%d:%d)",__FUNCTION__,  tag->pos, tag->length, tag->data->len, tag->data->tagLen);
    }
    log_message (LOG_INFO, "%s: size=%d in_size=%d",__FUNCTION__,  dst->size, dst->in_size);
#endif

    return len;
}

int init_stream_for_slave(struct stream_s *dst, struct stream_s *src)
{
    struct flvtag_s *newtag;
    struct flvtag_s *oritag;

    oritag = src->pre_tags_head;

    while(oritag) {
        if (!(newtag = makenewtag (oritag->data, oritag->length))) {
            return -1;
        }
        newtag->time_stamp = 0;
        newtag->data->refCnt++;
        if (dst->size == 0) {
            LIST_HEAD (dst) = LIST_TAIL (dst) = newtag;
        } else {
            LIST_TAIL (dst)->next = newtag;
            LIST_TAIL (dst) = newtag;
        }
        dst->size += oritag->length;
        dst->in_size += oritag->length;
        oritag = oritag->next;
    }
    
#if 0
    {
        struct flvtag_s *tag;

        g_dbg_st = dst;
        tag = src->pre_tags_head;
        log_message (LOG_INFO, "%s: size=%d in_size=%d", __FUNCTION__, dst->size, dst->in_size);
        while(tag) {
            log_message (LOG_INFO, "%s: tag(%d:%d) data(%d:%d)", __FUNCTION__, tag->pos, tag->length, tag->data->len, tag->data->tagLen);
            tag = tag->next;
        }
    }
#endif
    return 0;
}


int g_p2pFd=-1;
struct shm_s *g_shm=NULL;

int p2p_mem_prepare(char *filename)
{
    g_p2pFd = open(filename, O_RDWR, 0);
    if (g_p2pFd < 0) {
        log_message (LOG_ERR, "p2p_mem_prepare open failed! %s", strerror(errno));
        return -1;
    }

    if (ftruncate(g_p2pFd, P2P_SHARE_MEM_SIZE) < 0) {
        log_message (LOG_ERR, "ftruncate to size %d failed! %s", P2P_SHARE_MEM_SIZE, strerror(errno));
        close(g_p2pFd);
        return -1;
    }

    g_shm = (struct shm_s *)mmap(NULL, sizeof(struct shm_s), PROT_READ|PROT_WRITE, MAP_SHARED, g_p2pFd, 0);
    if (g_shm < 0) {
        log_message (LOG_ERR, "p2p_mem_prepare mmap failed! %s", strerror(errno));
        close(g_p2pFd);
        return -1;
    }

    return 0;
}

void p2p_mem_clear()
{
    munmap(g_shm, sizeof(struct shm_s));
    close(g_p2pFd);
}

/* ptpc -> transmission */
int st_writeDataToPiece(struct stream_s *st, struct flvtag_s *tag, size_t bytesin)
{
    char *buf=NULL;
    unsigned int len=bytesin;
    unsigned int curr_pieceEndOff=0;
    int w_len=0;
    struct p2p_piece_head_s p2p_pieceHead;

    if (!tag || !tag->data) {
        return -1;
    }

    buf = tag->data->string + tag->data->len - bytesin;

    if (g_shm->w_pieceIdx == 0) {
        g_shm->w_pieceIdx = st->curr_piece_index;
        g_shm->w_off = 0;
    }

    while(len) {
        if (g_shm->w_off % P2P_PIECE_SIZE == 0) {
            /* write piece head */
            if (tag->data->len == len) {
                p2p_pieceHead.next_tag_distance = 0;
            } else {
                p2p_pieceHead.next_tag_distance = htonl(tag->data->tagLen - tag->data->len - len);
            }
            p2p_pieceHead.piece_index = g_shm->w_pieceIdx;
            memcpy(g_shm->data+g_shm->w_off, &p2p_pieceHead, PIECE_HEAD_SIZE);
            g_shm->w_off += PIECE_HEAD_SIZE;
            continue;
        }

        curr_pieceEndOff = (g_shm->w_localPieceIdx+1) * P2P_PIECE_SIZE;

        if (g_shm->w_off + len < curr_pieceEndOff) {
            memcpy(g_shm->data+g_shm->w_off, buf, len);
            g_shm->w_off += len;
            return 0;
        } else {
            w_len = curr_pieceEndOff - g_shm->w_off;
            memcpy(g_shm->data+g_shm->w_off, buf, w_len);
            g_shm->w_pieceIdx++;
            g_shm->w_localPieceIdx++;
            g_shm->w_off = curr_pieceEndOff;
            if (g_shm->w_localPieceIdx == MAX_PIECE_COUNT) {
                g_shm->w_localPieceIdx = 0;
                g_shm->w_off = 0;
            }
            len -= w_len;
        }
    }
    return 0;
}

int st_parsePieceToStream(struct stream_s *st, unsigned int pieceIndex, unsigned int localPieceIdx)
{
    struct flvtag_s *tag=NULL;
    char *buf = g_shm->data + localPieceIdx*P2P_PIECE_SIZE;
    unsigned int idx = ntohl(*((unsigned int *)buf));
    unsigned int next_tag_dist = ntohl(*((unsigned int *)(buf+4)));
    unsigned int len=0, len1=0;

    if (!st) {
        return -1;
    }

    if( idx != pieceIndex) {
        log_message (LOG_ERR, "get pieceIndex %u, but expect %u!", idx, pieceIndex);
        return -1;
    }
    buf += 8;
    len = PIECE_DATA_SIZE-8;

    if (st->curr_piece_index == 0) {
        /* need to get the first tag */
        if (next_tag_dist >= len) {
            return 0;
        }

        buf += next_tag_dist;
        len -= next_tag_dist;
        st->curr_piece_index = pieceIndex;
        st->recv_st = FLV_WAIT_TAG_HDR;
        st->curr_len = 0;
    }

    while(len) {
        if (st->recv_st == FLV_WAIT_TAG_HDR) {
            len1 = FLV_TAG_HDR_LEN_EXT-st->curr_len;
            if (len >= len1) {
                int tag_len=0;
                struct dataNode *data;

                memcpy(st->tag_hdr+st->curr_len, buf, len1);

                tag_len = FLV_TAG_HDR_LEN_EXT + st->tag_hdr[5]*0x10000+st->tag_hdr[6]*0x100+st->tag_hdr[7]+4;
                data = (struct dataNode *)safemalloc(tag_len+(size_t)&(((struct dataNode *)0)->string));
                if (data == NULL) {
                    log_message (LOG_ERR, "read flv stream: ENOMEM");
                    return -3;
                }
                data->refCnt = 0;
                data->tagLen = tag_len;
                data->len = FLV_TAG_HDR_LEN_EXT;
                
                if (add_to_stream(st, data, FLV_TAG_HDR_LEN_EXT) < 0) {
                    safefree(data);
                    log_message (LOG_ERR, "can not add data to stream!");
                    return -4;
                }
                buf += FLV_TAG_HDR_LEN_EXT;
                len -=FLV_TAG_HDR_LEN_EXT;
                next_tag_dist = tag_len - FLV_TAG_HDR_LEN_EXT;
                st->recv_st = FLV_WAIT_TAG_END;
                continue;
            } else {
                memcpy(st->tag_hdr+st->curr_len, buf, len);
                buf += len;
                len -= len;
                break;
            }
        }

        if (st->recv_st == FLV_WAIT_TAG_END) {
            tag = LIST_TAIL (st);

            if (!tag) {
                return -1;
            }
            len1 = tag->data->tagLen - tag->data->len;

            if (len >= len1) {
                memcpy(tag->data+tag->data->len, buf, len1);
                buf += len1; 
                len -= len1;
                st->recv_st = FLV_WAIT_TAG_HDR;
                st->curr_len = 0;
            } else {
                memcpy(tag->data->string+tag->data->len, buf, len);
                tag->data->len += len;
                break;
            }
        }
    }
    st->curr_piece_index++;

    return 0;
}

int st_queuePiece(struct stream_s *st, unsigned int pieceIndex, unsigned int localPieceIdx)
{
    struct piece_s *newNode=NULL;
    struct piece_s *node0=NULL, *node1=NULL;

    newNode = (struct piece_s *) safemalloc (sizeof (struct piece_s));
    if (!newNode) {
        return -1;
    }
    newNode->piece_idx = pieceIndex;
    newNode->local_piece_idx = localPieceIdx;
    newNode->next = NULL;

    if (st->piece_head == NULL) {
        st->piece_head = newNode;
        return 0;
    }

    node0 = node1 = newNode;
    while(node1) {
        if (pieceIndex < node1->piece_idx) {
            newNode->next = node1;
            if (node0 == node1) {
                st->piece_head = newNode;
                return 0;
            }
            node0->next = newNode;
        }
        node0 = node1;
        node1 = node1->next;
    }

    node0->next = newNode;
    return 0;
}

int st_parseDataFromPieceQueue(struct stream_s *st)
{
    struct piece_s *node=NULL;

    while(st->piece_head) {
        node = st->piece_head;
        if (node->piece_idx == st->curr_piece_index) {
            if (st_parsePieceToStream(st, node->piece_idx, node->local_piece_idx)<0) {
                log_message (LOG_ERR, "stream error: %s %d", __FUNCTION__, __LINE__);
                return -1;
            }
        
            st->piece_head = node->next;
            safefree(node);
        }
    }

    return 0;
}

/* transmission -> ptpc */
int st_readDataFromPiece(struct stream_s *st, unsigned int pieceIndex, unsigned int localPieceIdx)
{
    if (st->curr_piece_index == pieceIndex) {
        /* parse this piece and insert to stream */
        if (st_parsePieceToStream(st, pieceIndex, localPieceIdx)<0) {
            log_message (LOG_ERR, "stream error: %s %d", __FUNCTION__, __LINE__);
            return -1;
        }
        
        return st_parseDataFromPieceQueue(st);
    } else if (st->curr_piece_index > pieceIndex) {
        /* just ignore pieces which we already have */
    } else if (st->curr_piece_index == 0) {
        /* parse this piece and insert to stream */
        if (st_parsePieceToStream(st, pieceIndex, localPieceIdx)<0) {
            log_message (LOG_ERR, "stream error: %s %d", __FUNCTION__, __LINE__);
            return -1;
        }
    } else {
        return st_queuePiece(st, pieceIndex, localPieceIdx);
    }

    return 0;
}
/* *********************************
 * stream  slice end 
 * *********************************/
