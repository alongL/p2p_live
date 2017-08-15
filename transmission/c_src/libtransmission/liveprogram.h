#include "transmission.h"
#include "torrent.h"

#define MAX_SHM_SIZE 32
#define MAX_RESID_LEN 64

int tr_shmInit(char *filename);


void tr_shmUninit();


void *tr_getShmBaseAddr();


/*tr_torrent *
tr_LiveProgramNew (const tr_ctor * ctor, int * setme_error, int * setme_duplicate_id);*/


int tr_SendLiveProgramAnnounce(void);

void
tr_shmInsertNode(tr_torrent *tor,
        tr_piece_index_t pieceIndex,
        tr_piece_index_t localPieceIndex);

