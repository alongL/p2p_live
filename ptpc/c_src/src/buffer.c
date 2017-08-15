/* tinyproxy - A fast light-weight HTTP proxy
 * Copyright (C) 1999, 2001 Robert James Kaes <rjkaes@users.sourceforge.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/* The buffer used in each connection is a linked list of lines. As the lines
 * are read in and written out the buffer expands and contracts. Basically,
 * by using this method we can increase the buffer size dynamically. However,
 * we have a hard limit of 64 KB for the size of the buffer. The buffer can be
 * thought of as a queue were we act on both the head and tail. The various
 * functions act on each end (the names are taken from what Perl uses to act on
 * the ends of an array. :)
 */

#include "main.h"
#include "heap.h"
#include "buffer.h"
#include "log.h"

#define BUFFER_HEAD(x) (x)->head
#define BUFFER_TAIL(x) (x)->tail

extern int allow_debug;
#define ALLOW_DEBUG if(allow_debug == 1) {log_message (LOG_INFO, "------%s %d", __FUNCTION__, __LINE__);}
/* #define DATA_NODE_DEBUG 1 */

struct dataNode {
    unsigned int refCnt;
#ifdef DATA_NODE_DEBUG
    struct dataNode *next;
#endif
    unsigned char string[];  /* the actual string of data */
};

struct bufline_s {
    struct dataNode *data;
    size_t length;          /* length of the string of data */
    size_t pos;             /* start sending from this offset */
    int tag_pos;
    struct bufline_s *next; /* pointer to next in linked list */
};

/*
 * The buffer structure points to the beginning and end of the buffer list
 * (and includes the total size)
 */
struct buffer_s {
    struct bufline_s *head; /* top of the buffer */
    struct bufline_s *tail; /* bottom of the buffer */
    size_t size;            /* total size of the buffer */
    size_t in_size;            /* total size of the buffer */
    size_t out_size;            /* total size of the buffer */
};

#ifdef DATA_NODE_DEBUG
struct dn_debug_s {
    struct dataNode *head;
    struct dataNode *tail;
    unsigned int alloc;
    unsigned int free;
};

struct dn_debug_s dn_debug;

void add_to_dn_debug(struct dataNode *node)
{
    if (dn_debug.head == NULL) {
        dn_debug.head = node;
        dn_debug.tail = node;
    } else {
        dn_debug.tail->next = node;
        dn_debug.tail = node;
    }
    dn_debug.alloc++;
}

void rm_from_dn_debug(struct dataNode *node)
{
    struct dataNode *temp=NULL;
    
    if (dn_debug.head == node && dn_debug.tail == node) {
        dn_debug.head = NULL;
        dn_debug.tail = NULL;
        dn_debug.free++;
        return;
    }

    if (dn_debug.head == node) {
        dn_debug.head = node->next;
        dn_debug.free++;
        return;
    }

    temp=dn_debug.head;

    while(temp) {
        if (temp->next == node) {
            if (dn_debug.tail == node) {
                dn_debug.tail = temp;
            }
            temp->next=node->next;
            dn_debug.free++;
            return;
        }
        temp = temp->next;
    }
}
#endif

void dn_debug_init(void)
{
#ifdef DATA_NODE_DEBUG
    dn_debug.head = NULL;
    dn_debug.tail = NULL;
    dn_debug.alloc = 0;
    dn_debug.free = 0;
#endif
}

static void print_dn_debug()
{
#ifdef DATA_NODE_DEBUG
    struct dataNode *node=dn_debug.head;
    while(node) {
        log_message (LOG_CONN, "node:%p refCnt:%d", node, node->refCnt);
        node = node->next;
    }
#endif
}

void print_buffer_info (struct buffer_s * buffptr)
{
    struct bufline_s *line;

    assert (buffptr != NULL);

#ifdef DATA_NODE_DEBUG
    log_message (LOG_INFO, "======buffptr: %p, size=%d, in=%d, out=%d alloc=%d free=%d", 
            buffptr, buffptr->size, buffptr->in_size, buffptr->out_size,
            dn_debug.alloc, dn_debug.free); 
#else
    log_message (LOG_INFO, "======buffptr: %p, size=%d, in=%d, out=%d", 
            buffptr, buffptr->size, buffptr->in_size, buffptr->out_size);
#endif
    print_dn_debug();

    if (buffptr->size == 0)
        return;

    assert (BUFFER_HEAD (buffptr) != NULL);
    line = BUFFER_HEAD (buffptr);

    while(line) {
        log_message (LOG_INFO, "======line: %p, refCnt=%d", line, line->data->refCnt); 
        line = line->next;
    }
    return;
}

void save_tag(char *ptr, int len);
void print_all_tags(void);
void parse_flv_ho_stream_data(struct buffer_s * buffptr);

struct bufline_s *g_line=NULL;

/*
 * Take a string of data and a length and make a new line which can be added
 * to the buffer. The data IS copied, so make sure if you allocated your
 * data buffer on the heap, delete it because you now have TWO copies.
 */
static struct bufline_s *makenewline (unsigned char *data, size_t length)
{
    struct bufline_s *newline;

    assert (data != NULL);
    assert (length > 0);

    newline = (struct bufline_s *) safemalloc (sizeof (struct bufline_s));
    if (!newline)
        return NULL;

    newline->data = (struct dataNode *) safemalloc (length+(size_t)&(((struct dataNode *)0)->string));
    if (!newline->data) {
        safefree (newline);
        return NULL;
    }
#ifdef DATA_NODE_DEBUG
    newline->data->next = NULL;
    add_to_dn_debug(newline->data);
#endif

    newline->data->refCnt = 0;
    memcpy (newline->data->string, data, length);
    newline->length = length;
    newline->pos = 0;
    newline->tag_pos = -1;
    newline->next = NULL;

    return newline;
}

/*
 * Free the allocated buffer line
 */
static void free_line (struct bufline_s *line)
{
    assert (line != NULL);

    if (!line)
        return;

    if (line->data) {
        if (line->data->refCnt==0) {
#ifdef DATA_NODE_DEBUG
            rm_from_dn_debug(line->data);
#endif
            safefree (line->data);
        } else {
            if (line->data->refCnt<0 || line->data->refCnt>3) {
                log_message (LOG_INFO, "======refCnt=%d line=%p", line->data->refCnt, line);
            }
        }
    }
    if (line == g_line) {
        log_message (LOG_CONN, "[MASTER] %s %d g_line=%p pos=%d tag_pos=%d len=%d",
                __FUNCTION__, __LINE__, g_line, g_line->pos, g_line->tag_pos, g_line->length);
        g_line=NULL;
        /*allow_debug = 1;*/
    }


    safefree (line);
}

/*
 * Create a new buffer
 */
struct buffer_s *new_buffer (void)
{
        struct buffer_s *buffptr;

        buffptr = (struct buffer_s *) safemalloc (sizeof (struct buffer_s));
        if (!buffptr)
                return NULL;

        /*
         * Since the buffer is initially empty, set the HEAD and TAIL
         * pointers to NULL since they can't possibly point anywhere at the
         * moment.
         */
        BUFFER_HEAD (buffptr) = BUFFER_TAIL (buffptr) = NULL;
        buffptr->size = 0;

        return buffptr;
}

/*
 * Delete all the lines in the buffer and the buffer itself
 */
void delete_buffer (struct buffer_s *buffptr)
{
    struct bufline_s *next;

    assert (buffptr != NULL);

    while (BUFFER_HEAD (buffptr)) {
        next = BUFFER_HEAD (buffptr)->next;
        BUFFER_HEAD (buffptr)->data->refCnt--;
        free_line (BUFFER_HEAD (buffptr));
        BUFFER_HEAD (buffptr) = next;
    }

    safefree (buffptr);
}

/*
 * Return the current size of the buffer.
 */
size_t buffer_size (struct buffer_s *buffptr)
{
    return buffptr->size;
}

int clone_buffer(int need_tag_head, struct buffer_s *dst, struct buffer_s *src) 
{
    struct bufline_s *oriline;
    struct bufline_s *newline;
    int len=0;
    unsigned char *ptr=NULL;

    assert (dst != NULL);
    assert (src != NULL);
    
    assert (BUFFER_TAIL (src) != NULL);
    oriline = BUFFER_TAIL(src);

    if (oriline->length == 0) {
        return 0;
    }

    if (need_tag_head) {
        if (oriline->tag_pos == -1) {
            return 0;
        }

        len = oriline->length - oriline->tag_pos;
        if (len <= 0) {
            return 0;
        }

        ptr = (char*)&(oriline->data->string[oriline->tag_pos]);
        if (!(newline = makenewline (ptr, len))) {
            return -1;
        }
        log_message (LOG_CONN, "[MASTER] clone from next tag success! %02x %02x %02x %02x line=%p pos=%d tag_pos=%d len=%d",
                *ptr, *(ptr+1), *(ptr+2), *(ptr+3), newline, oriline->pos, oriline->tag_pos, oriline->length);
        g_line = newline;
    } else {
        if (!(newline = (struct bufline_s *) safemalloc (sizeof (struct bufline_s)))) {
            return -1;
        }
        len = oriline->length;
        newline->data = oriline->data;
        newline->length = len;
        newline->pos = 0;
        newline->tag_pos = -1;
        newline->next = NULL;
    }

    newline->data->refCnt++;

    if (dst->size == 0) {
        BUFFER_HEAD (dst) = BUFFER_TAIL (dst) = newline;
    } else {
        BUFFER_TAIL (dst)->next = newline;
        BUFFER_TAIL (dst) = newline;
    }

    dst->size += len;
    dst->in_size += len;

    if (newline == g_line) {
        log_message (LOG_CONN, "[MASTER] %s %d g_line=%p pos=%d tag_pos=%d len=%d buffer_size=%d",
                __FUNCTION__, __LINE__, newline, newline->pos, newline->tag_pos, newline->length,dst->size);
    }

    return len;
}

/*
 * Push a new line on to the end of the buffer.
 */
int add_to_buffer (struct buffer_s *buffptr, unsigned char *data, size_t length)
{
    struct bufline_s *newline;

    assert (buffptr != NULL);
    assert (data != NULL);
    assert (length > 0);

    /*
     * Sanity check here. A buffer with a non-NULL head pointer must
     * have a size greater than zero, and vice-versa.
     */
    if (BUFFER_HEAD (buffptr) == NULL)
        assert (buffptr->size == 0);
    else
        assert (buffptr->size > 0);

    /*
     * Make a new line so we can add it to the buffer.
     */
    if (!(newline = makenewline (data, length)))
        return -1;

    if (buffptr->size == 0)
        BUFFER_HEAD (buffptr) = BUFFER_TAIL (buffptr) = newline;
    else {
        BUFFER_TAIL (buffptr)->next = newline;
        BUFFER_TAIL (buffptr) = newline;
    }

    buffptr->size += length;
    buffptr->in_size += length;
    newline->data->refCnt++;

    return 0;
}

/*
 * Remove the first line from the top of the buffer
 */
static struct bufline_s *remove_from_buffer (struct buffer_s *buffptr)
{
    struct bufline_s *line;

    assert (buffptr != NULL);
    assert (BUFFER_HEAD (buffptr) != NULL);

    line = BUFFER_HEAD (buffptr);
    BUFFER_HEAD (buffptr) = line->next;

    buffptr->size -= line->length;
    buffptr->out_size += line->length;
    line->data->refCnt--;

    return line;
}

/*
 * Reads the bytes from the socket, and adds them to the buffer.
 * Takes a connection and returns the number of bytes read.
 */
#define READ_BUFFER_SIZE (1024 * 2)
ssize_t read_buffer (int fd, struct buffer_s * buffptr)
{
    ssize_t bytesin;
    unsigned char *buffer;

    assert (fd >= 0);
    assert (buffptr != NULL);

    /*
     * Don't allow the buffer to grow larger than MAXBUFFSIZE
     */
    if (buffptr->size >= MAXBUFFSIZE)
        return 0;

    buffer = (unsigned char *) safemalloc (READ_BUFFER_SIZE);
    if (!buffer) {
        log_message (LOG_ERR, "readbuff: ENOMEM");
        return -ENOMEM;
    }

    bytesin = read (fd, buffer, READ_BUFFER_SIZE);

    if (bytesin > 0) {
        if (add_to_buffer (buffptr, buffer, bytesin) < 0) {
            log_message (LOG_ERR, "readbuff: add_to_buffer() error.");
            bytesin = -1;
        }
    } else {
        if (bytesin == 0) {
            /* connection was closed by client */
            log_message (LOG_ERR, "readbuff: bytesin == 0");
            bytesin = -1;
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
                    bytesin = 0;
                    break;
                default:
                    log_message (LOG_ERR,
                            "readbuff: recv() error \"%s\" on file descriptor %d",
                            strerror (errno), fd);
                    bytesin = -1;
                    break;
            }
        }
    }

    safefree (buffer);
    return bytesin;
}

/*
 * Write the bytes in the buffer to the socket.
 * Takes a connection and returns the number of bytes written.
 */
ssize_t write_buffer (int fd, struct buffer_s * buffptr)
{
    ssize_t bytessent;
    struct bufline_s *line;

    assert (fd >= 0);
    assert (buffptr != NULL);

    if (buffptr->size == 0){
        return 0;
    }

    /* Sanity check. It would be bad to be using a NULL pointer! */
    assert (BUFFER_HEAD (buffptr) != NULL);
    line = BUFFER_HEAD (buffptr);

    if (line == g_line) {
        log_message (LOG_CONN, "[MASTER] %s %d fd=%d g_line=%p pos=%d tag_pos=%d len=%d buffer_size=%d",
                __FUNCTION__, __LINE__, fd, g_line, g_line->pos, g_line->tag_pos, g_line->length,buffptr->size);
    }
    bytessent = send (fd, line->data->string + line->pos, line->length - line->pos, MSG_NOSIGNAL);

    if (bytessent >= 0) {
        /* bytes sent, adjust buffer */
        line->pos += bytessent;
        if (line->pos == line->length) {
            free_line (remove_from_buffer (buffptr));
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
                log_message (LOG_ERR,
                        "writebuff: write() error [NOBUFS/NOMEM] \"%s\" on "
                        "file descriptor %d", strerror (errno),
                        fd);
                return 0;
            default:
                log_message (LOG_ERR,
                        "writebuff: write() error \"%s\" on fd %d line=%p pos=%d len=%d",
                        strerror (errno), fd, line, line->pos, line->length);
    if (line == g_line) {
        log_message (LOG_CONN, "[MASTER] %s %d g_line=%p pos=%d tag_pos=%d len=%d buffer_size=%d",
                __FUNCTION__, __LINE__, g_line, g_line->pos, g_line->tag_pos, g_line->length,buffptr->size);
    }
                return -1;
        }
    }
}

int remove_buffer_first_line (struct buffer_s * buffptr)
{
    struct bufline_s *line;

    assert (buffptr != NULL);

    if (buffptr->size == 0)
        return 0;

    assert (BUFFER_HEAD (buffptr) != NULL);
    line = BUFFER_HEAD (buffptr);

    line->pos = line->length;
    free_line (remove_from_buffer (buffptr));
    return 0;
}



enum parse_s {
    WAIT_FLV_START,
    AT_TAG_START,
    WAIT_DATASIZE,
    WAIT_TAIMESTAMP,
    WAIT_NEXTTAG
};

struct flv_d {
    int pid;
    enum parse_s parse_state;
    unsigned int wait_ds_len;
    unsigned int data_size;
    unsigned int wait_ts_len;
    unsigned int wait_tag_len; 
};

#define TAG_NUM 8
unsigned char tag[TAG_NUM][8];
int tag_len[TAG_NUM];
int tag_idx=0;

struct flv_d flv_stream;

void init_flv_stream_st(void)
{
    memset((void*)&flv_stream, 0, sizeof(struct flv_d));
    flv_stream.parse_state = WAIT_FLV_START;
    flv_stream.pid = getpid();
    memset(tag, 0, sizeof(tag));
    tag_idx=0;
}

static void print_fl_stream_st(void) {
    log_message (LOG_INFO, "parse_state=%d", flv_stream.parse_state);
}

void save_tag(char *ptr, int len)
{
    int i=0;
    for(i=0;i<8;i++) {
        tag[tag_idx][i] = *(ptr+i);
    }
    tag_len[tag_idx] = len;
    tag_idx++;
    if(TAG_NUM==tag_idx) {
        tag_idx=0;
    }
}

void print_all_tags(void)
{
    int i=0;

    log_message (LOG_INFO, "========== tag_idx=%d ==========", tag_idx);
    for(i=0;i<TAG_NUM;i++) {
        log_message (LOG_INFO, "%02x %02x %02x %02x %02x %02x %02x %02x len=%d",
                tag[i][0], tag[i][1], tag[i][2], tag[i][3],
                tag[i][4], tag[i][5], tag[i][6], tag[i][7],
                tag_len[i]);
    }
}


int parse_flv_line(struct bufline_s *line, unsigned int *offset, int debug)
{
    unsigned int i=0;
    unsigned char* ptr;

    assert (line != NULL);

    if (*offset == line->length) {
        return 0;
    } else if (*offset > line->length) {
        log_message (LOG_INFO, "#### offset=%d line->length=%d ####", *offset, line->length);
        return -1;
    }
 
    ptr = line->data->string + *offset;
    if (flv_stream.parse_state == WAIT_FLV_START) {
        log_message (LOG_INFO, "======WAIT_FLV_START len=%d offset=%d %02x %02x %02x %02x======", line->length, *offset,
                *(ptr), *(ptr+1), *(ptr+2), *(ptr+3));
        i=0;
        while(i<line->length-3) {
            if (*(ptr+i) == 0x46 && *(ptr+i+1) == 0x4c && *(ptr+i+2) == 0x56) {
                *offset = i+13;
                flv_stream.parse_state = AT_TAG_START;

                ptr = line->data->string+*offset;
                return parse_flv_line(line, offset, debug);
            }
            i++;
        }
    } else if (flv_stream.parse_state == AT_TAG_START) {
        if ( *ptr != 0x08 && *ptr != 0x09 && *ptr != 0x12) {
            log_message (LOG_INFO, "TAG ERROR!", tag_idx);
            print_all_tags();
        }
        tag[tag_idx][0] = line->data->string[*offset];
        line->tag_pos = *offset;
        flv_stream.parse_state = WAIT_DATASIZE;
        flv_stream.wait_ds_len = 3;
        flv_stream.data_size = 0;
        (*offset)++;
        return parse_flv_line(line, offset, debug);
    } else if (flv_stream.parse_state == WAIT_DATASIZE) {
        if(line->length - *offset >= flv_stream.wait_ds_len) {
            for(i=0;i<flv_stream.wait_ds_len; i++) {
                tag[tag_idx][1+i] = line->data->string[*offset];
                flv_stream.data_size = flv_stream.data_size*256 + *(ptr++);
                (*offset)++;
            }
            flv_stream.parse_state = WAIT_TAIMESTAMP;
            flv_stream.wait_ts_len = 3;
        } else {
            while(*offset < line->length) {
                tag[tag_idx][1+3-flv_stream.wait_ds_len] = line->data->string[*offset];
                flv_stream.data_size = flv_stream.data_size*256 + *(ptr++);
                flv_stream.wait_ds_len--;
                (*offset)++;
            }
        }
        return parse_flv_line(line, offset, debug);
    } else if (flv_stream.parse_state == WAIT_TAIMESTAMP) {
        if(line->length - *offset >= flv_stream.wait_ts_len) {
            for(i=0; i<flv_stream.wait_ts_len; i++) {
                /**(ptr++) = 0;*/
                tag[tag_idx][4+i] = line->data->string[*offset];
                (*offset)++;
            }
            flv_stream.parse_state = WAIT_NEXTTAG;
            flv_stream.wait_tag_len = 8+flv_stream.data_size;
            tag[tag_idx][7] = line->data->string[*offset];
            tag_idx++;
            if (tag_idx==TAG_NUM) {
                tag_idx=0;
            }
        } else {
            while(*offset < line->length) {
                /**(ptr++) = 0;*/
                tag[tag_idx][1+3-flv_stream.wait_ts_len] = line->data->string[*offset];
                flv_stream.wait_ts_len--;
                (*offset)++;
            }
        }
        return parse_flv_line(line, offset, debug);
    } else if (flv_stream.parse_state == WAIT_NEXTTAG) {
        if(line->length - *offset >= flv_stream.wait_tag_len) {
            *offset += flv_stream.wait_tag_len;
            flv_stream.parse_state = AT_TAG_START;
            tag_len[tag_idx] = line->length - *offset;
            ptr = line->data->string+*offset;
            if (line->length > *offset) {
                if ((*ptr != 0x09 && *ptr != 0x08 && *ptr != 0x12) || debug) {
                    log_message (LOG_INFO, "TAG: %02x %02x %02x %02x %02x %02x %02x %02x, pid=%d len=%d",
                            *(ptr), *(ptr+1), *(ptr+2), *(ptr+3), *(ptr+4), *(ptr+5), *(ptr+6), *(ptr+7),
                            flv_stream.pid, line->length-*offset);
                }
            }
        } else {
            flv_stream.wait_tag_len -=(line->length - *offset);
            *offset = line->length;
        }
        return parse_flv_line(line, offset, debug);
    }
}

char g_magic[2][8]={
    {0x12, 0x34,0x56,0x12,0x34,0x56,0x88,0x99},
    {0x12, 0x34,0x56,0x12,0x34,0x56,0x88,0x99}
};
void parse_flv_stream_data(struct buffer_s * buffptr, int direct, int debug)
{
    struct bufline_s *line;
    unsigned int offset=0;
#if 0
    char *ptr;
    int i=0;
    char magic[8]={0};
#endif

    assert (buffptr != NULL);

    if (buffptr->size == 0)
        return;

    if (direct == 0) { /* recv */
        assert (BUFFER_TAIL (buffptr) != NULL);
        line = BUFFER_TAIL (buffptr);
    } else { /* send */
        assert (BUFFER_HEAD(buffptr) != NULL);
        line = BUFFER_HEAD(buffptr);
        return;
    }

#if 0
    ptr = line->data->string + line->pos;
    for(i=0; i<8; i++) {
        magic[i] = *(ptr+i);
    }
    if (memcmp(magic, g_magic[direct], 8) == 0) {
        log_message (LOG_INFO, "repeat line:%02x %02x %02x %02x %02x %02x %02x %02x flv_stream.parse_state=%d offset=%d",
                *(ptr), *(ptr+1), *(ptr+2), *(ptr+3), *(ptr+4), *(ptr+5), *(ptr+6), *(ptr+7),
                flv_stream.parse_state,line->pos);
        return;
    }
    memcpy(g_magic, magic, 8);
#endif


    offset=line->pos;
    parse_flv_line(line, &offset, debug);
}

void parse_flv_ho_stream_data(struct buffer_s * buffptr) 
{
    struct bufline_s *line;
    unsigned int offset=0;
    unsigned char *ptr=NULL;

    assert (buffptr != NULL);

    if (buffptr->size == 0)
        return;

    assert (BUFFER_HEAD(buffptr) != NULL);
    line = BUFFER_HEAD(buffptr);


    print_fl_stream_st();

    if (line) {
        log_message (LOG_INFO, "%s %d: line=%p line->data=%p", __FUNCTION__, __LINE__, line, line->data);
        ptr = &line->data->string[line->pos];
        log_message (LOG_INFO, "start of slavebuff is %02x %02x %02x %02x %02x %02x %02x %02x",
                *(ptr), *(ptr+1), *(ptr+2), *(ptr+3), *(ptr+4), *(ptr+5), *(ptr+6), *(ptr+7));
    }

    if (flv_stream.parse_state != AT_TAG_START) {
        flv_stream.parse_state = AT_TAG_START;
    }

    while(line) {
        offset=line->pos;
        parse_flv_line(line, &offset, 1);
        line = line->next;
    }
    log_message (LOG_INFO, "%s %d: Exit.", __FUNCTION__, __LINE__);
}

int terminate_server_buffer_at_tag_end(struct buffer_s * buffptr)
{
    struct bufline_s *line;

    assert (buffptr != NULL);

    if (buffptr->size == 0)
        return 0;

    assert (BUFFER_TAIL (buffptr) != NULL);
    line = BUFFER_TAIL (buffptr);
    assert (line->length > line->tag_pos);

    if (line->tag_pos != -1) {
        buffptr->size = buffptr->size - (line->length - line->tag_pos);
        line->length = line->tag_pos;
        return 1;
    }

    return 0;
}

int move_buffers(struct buffer_s * dst, struct buffer_s * src)
{
    assert (src != NULL);
    assert (dst != NULL);

    if (src->size == 0) {
        log_message (LOG_INFO, "There is nothing in source buffer");
        return 0;
    }


    assert (BUFFER_HEAD (src) != NULL);
    assert (BUFFER_TAIL (src) != NULL);


    if (dst->size == 0) {
        BUFFER_HEAD (dst) = BUFFER_HEAD (src);
        BUFFER_TAIL (dst) = BUFFER_TAIL (src);
    } else {
        assert (BUFFER_HEAD (dst) != NULL);
        assert (BUFFER_TAIL (dst) != NULL);

        BUFFER_TAIL (dst)->next = BUFFER_HEAD (src);
        BUFFER_TAIL (dst) = BUFFER_TAIL (src);
    }

    dst->size += src->size;
    BUFFER_HEAD (src) = NULL;
    BUFFER_TAIL (src) = NULL;

    log_message (LOG_CONN, "move %d bytes from source to dst", src->size);

    return 1;
}
