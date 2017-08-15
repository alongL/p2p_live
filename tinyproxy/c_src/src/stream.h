#ifndef __STREAM_H__
#define __STREAM_H__

#define MAX_SEND_LEN (1024*2)
#define FLV_HDR_LEN 13
#define FLV_TAG_HDR_LEN 11
/* #define TAG_STREAM_DEBUG 1 */


#define LIST_HEAD(x) (x)->head
#define LIST_TAIL(x) (x)->tail

enum flvrecv_e {
    FLV_WAIT_HDR=0,
    FLV_WAIT_TAG_HDR,
    FLV_WAIT_TAG_END
};

struct dataNode {
    unsigned int refCnt;
    unsigned int tagLen;
    unsigned int len;
#ifdef TAG_STREAM_DEBUG
    struct dataNode *next;
#endif
    unsigned char string[];  /* the actual string of data */
};

struct flvtag_s {
    struct dataNode *data;
    unsigned int time_stamp;
    size_t length;          /* length of the string of data */
    size_t pos;             /* start sending from this offset */
    struct flvtag_s *next; /* pointer to next in linked list */
};

struct stream_s {
    enum flvrecv_e recv_st;
    int curr_len;
    unsigned char hdr[FLV_HDR_LEN];
    unsigned char tag_hdr[FLV_TAG_HDR_LEN];
    int tag_flag;
    struct flvtag_s *pre_tags_head;     /* */
    struct flvtag_s *pre_tags_tail;     /* */
    int ts_delta;

    struct flvtag_s *head;         /* top of the tag */
    struct flvtag_s *tail;         /* bottom of the tag */
    size_t size;                   /* total size of all tags */
    size_t in_size;                /* total in size of the stream */
    size_t out_size;               /* total out size of the stream */
};

size_t stream_size (struct stream_s *streamptr);
struct stream_s *new_stream(void);
void delete_stream (struct stream_s *streamptr);
ssize_t read_flv_stream (int fd, struct stream_s *streamptr);
ssize_t write_flv_stream (int fd, struct stream_s *streamptr);
int init_flv_recv_stream(void);
int clone_stream_data(struct stream_s *dst, struct stream_s *src);
int init_stream_for_slave(struct stream_s *dst, struct stream_s *src);
void print_stream_info (struct stream_s * streamptr);
#endif
