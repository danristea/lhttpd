#ifndef _HTTPD_AIO_
#define _HTTPD_AIO_

#include "event.h"
#include "queue.h"

//#define MAX_AIO (sysconf(_SC_AIO_MAX))
#define MAX_AIO (_SC_AIO_MAX)
#define MAX_LISTIO (sysconf(_SC_AIO_LISTIO_MAX))

typedef struct aio_data {
    FILE* f;
    int fd;
    char *buf;
    int len;
    int pos;
    int flen;
    int ready;
    void *ctx;
    LIST_ENTRY(aio_data) next;
} aio_data;

struct async_io {
    long aid;
    void *sigd;
    int ac;
    int nc;
    int wait;
    void *nlist;
    void *alist;
};


struct async_io *aio_init(int pipe[2]);
//void schedule_aio_read(struct async_io *aio, struct aio_data *aio_d, void *ctx, int fd, char *buf, int len, int pos);
//void schedule_aio_read(struct async_io *aio, struct aio_data *aio_d, void *ctx, int fd, char *buf, int len, int pos);
void schedule_aio_read(struct async_io *aio, struct aio_data *aio_d);
void schedule_aio_write(struct async_io *aio, struct aio_data *aio_d);
void lh_aio_schedule(struct async_io *aio, void *ctx);
//int lh_aio_reap(void *alist, struct aio_data *aio_d[], int ac);
int lh_aio_reap(struct async_io *aio, struct aio_data *aio_d[], int ac);

//#define AIO_SIGD() aio_sigd()
#define AIO_INIT(pipe) aio_init(pipe)

#endif
