#ifndef __STREAM_H__
#define __STREAM_H__

#define MAX_SEND_LEN (1024*2)
#define FLV_HDR_LEN 13
#define FLV_HDR_LEN_EXT (FLV_HDR_LEN+4)
#define FLV_TAG_HDR_LEN 11
#define FLV_TAG_HDR_LEN_EXT (FLV_TAG_HDR_LEN+4)
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
    unsigned int len;        /* current len of tag buff */
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

struct piece_s {
    unsigned int piece_idx;
    unsigned int local_piece_idx;
    struct piece_s *next;
};

struct stream_s {
    enum flvrecv_e recv_st;
    unsigned int curr_len;
    unsigned char hdr[FLV_HDR_LEN_EXT];
    unsigned char tag_hdr[FLV_TAG_HDR_LEN_EXT];
    int tag_flag;
    struct flvtag_s *pre_tags_head;     /* */
    struct flvtag_s *pre_tags_tail;     /* */
    int ts_delta;
    unsigned int last_recv_ts;
    unsigned int last_send_ts;
    unsigned int curr_piece_index;
    struct piece_s *piece_head;

    struct flvtag_s *head;         /* top of the tag */
    struct flvtag_s *tail;         /* bottom of the tag */
    size_t size;                   /* total size of all tags */
    size_t in_size;                /* total in size of the stream */
    size_t out_size;               /* total out size of the stream */
    size_t p2p_size;               /* total out size of the stream */
};

size_t stream_size (struct stream_s *streamptr);
struct stream_s *new_stream(void);
void delete_stream (struct stream_s *streamptr);
ssize_t read_flv_stream (int fd, struct stream_s *streamptr, int isP2P);
ssize_t write_flv_stream (int fd, struct stream_s *streamptr, int isP2P);
int init_flv_recv_stream(void);
int clone_stream_data(struct stream_s *dst, struct stream_s *src);
int init_stream_for_slave(struct stream_s *dst, struct stream_s *src);
void print_stream_info (struct stream_s * streamptr);



/* *********************************
 *  * stream  slice start 
 *   * *********************************/
#define P2P_PIECE_SIZE (64*1024) /* 0.5M bits */
#define MAX_PIECE_COUNT 32
#define P2P_SHARE_MEM_DATA_SIZE (P2P_PIECE_SIZE*MAX_PIECE_COUNT) /* 16M bits - 2M Bytes */

struct shm_s {
        char data[P2P_SHARE_MEM_DATA_SIZE];
            unsigned int w_off;            /* write off in share memory */
                unsigned int w_localPieceIdx;  /* piece index in share memory */
                    unsigned int w_pieceIdx;     /* global piece index in streaming flow */
};

struct p2p_piece_head_s {
        unsigned int piece_index;
            unsigned int next_tag_distance;
};

#define PIECE_HEAD_SIZE sizeof(struct p2p_piece_head_s)
#define PIECE_DATA_SIZE (P2P_PIECE_SIZE-PIECE_HEAD_SIZE)
#define P2P_SHARE_MEM_SIZE sizeof(struct shm_s)



#endif
