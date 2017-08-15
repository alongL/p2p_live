#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
//#include "transmission.h"
//#include "torrent.h"
#include "liveprogram.h"

int liveProgramFd = -1;
void *liveProgramShm = NULL;
int shmSize = 0;


int tr_shmInit(char *filename)
{
    struct stat sb;

    liveProgramFd = open(filename, O_RDWR, 0);
    if (liveProgramFd < 0) 
    {
        return -1;
    }

    if ((fstat(liveProgramFd, &sb)) == -1)
    {
        return -1;
    }

    shmSize = sb.st_size;
    liveProgramShm = mmap(NULL, shmSize, PROT_READ|PROT_WRITE, MAP_SHARED, liveProgramFd, 0);
    if (liveProgramShm == NULL) {
        close(liveProgramFd);
        return -1;
    }

    return 0;
}

void tr_shmUninit()
{
    munmap(liveProgramShm, shmSize);
    close(liveProgramFd);
}

void *tr_getShmBaseAddr()
{

    return liveProgramShm;

}

/*tr_torrent *
tr_LiveProgramNew (const tr_ctor * ctor, int * setme_error, int * setme_duplicate_id)
{

    return tr_torrentNew(ctor, NULL, NULL);
}*/


int
tr_SendLiveProgramAnnounce(void)
{   
    int ret = 0;
    
    //ret = send_announce_peer()

    return ret;
}

void
tr_shmInsertNode(tr_torrent *tor,
                tr_piece_index_t pieceIndex,
                tr_piece_index_t localPieceIndex)
{
    tr_shmInfo *shmInfoNode = NULL;
    /* insert new node to head of shm list */
    shmInfoNode = tr_new(tr_shmInfo, 1);

    shmInfoNode->pieceIndex = pieceIndex;
    shmInfoNode->localPieceIndex = localPieceIndex;
    shmInfoNode->shmNext = tor->shmInfoList;
    tor->shmInfoList = shmInfoNode;

    return;
}
