/*
BSD 2-Clause License

Copyright (c) 2022, danristea
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include "httpd-aio.h"

/* linux */
#ifdef  __linux__

#define _GNU_SOURCE

#include <linux/aio_abi.h>
#include <sys/syscall.h>
#include <sys/eventfd.h>

inline int io_setup(unsigned nr, aio_context_t *ctxp) {
    return syscall(__NR_io_setup, nr, ctxp);
}

inline int io_destroy(aio_context_t ctx) {
    return syscall(__NR_io_destroy, ctx);
}

inline int io_submit(aio_context_t ctx, long nr, struct iocb **iocbpp) {
    return syscall(__NR_io_submit, ctx, nr, iocbpp);
}

inline int io_getevents(aio_context_t ctx, long min_nr, long max_nr, struct io_event *events, struct timespec *timeout) {
    return syscall(__NR_io_getevents, ctx, min_nr, max_nr, events, timeout);
}

static int op_code[] = {0, IOCB_CMD_PREAD, IOCB_CMD_PWRITE};

struct async_io *
aio_init(int pipe[2])
{
    struct async_io *aio;
    int rv;

    pipe[0] = pipe[1] = eventfd(0, EFD_NONBLOCK|EFD_CLOEXEC);

    aio = (struct async_io *) calloc(1, sizeof(struct async_io));
    assert(aio);

    aio->alist = (struct iocb*) calloc(MAX_AIO, sizeof(struct iocb));
    aio->nlist = (struct iocb*) calloc(MAX_AIO, sizeof(struct iocb));

    aio->sigd = &pipe[1];

    rv = io_setup(MAX_AIO, (aio_context_t *)&aio->aid);
    assert(rv == 0);

    aio->ac = 0;

    return aio;
}

void
schedule_aio(struct async_io *aio, struct aio_data *aio_d, short filter)
{
    struct iocb *acb = (struct iocb *) aio->nlist;

    memset(&acb[aio->nc], 0, sizeof(struct iocb));

    acb[aio->nc].aio_buf  = (uint64_t) (u_char *) aio_d->buf;
    acb[aio->nc].aio_nbytes = aio_d->len;
    acb[aio->nc].aio_offset = aio_d->pos;
    acb[aio->nc].aio_fildes = aio_d->fd;
    acb[aio->nc].aio_resfd = *(int *) aio->sigd;
    acb[aio->nc].aio_lio_opcode = op_code[filter];
    acb[aio->nc].aio_flags = IOCB_FLAG_RESFD;
    acb[aio->nc].aio_data = (uint64_t) (struct aio_data *)aio_d;

    aio->nc += 1;
}

void
lh_aio_schedule(struct async_io *aio, void *ctx)
{
//    struct iocb* rlist[MAX_AIO];
    struct iocb** rlist;
    struct iocb* alist;
    int rv;

    rlist = malloc(MAX_AIO * sizeof(struct iocb *));
    memcpy(aio->alist, aio->nlist, sizeof(struct iocb) * MAX_AIO);

    alist = (struct iocb*) aio->alist;

    for (int i = 0; i < aio->nc; i++)
        rlist[i] = &((struct iocb *)aio->alist)[i];

    struct iocb *acb_l = (struct iocb *)aio->alist;

    aio->ac = aio->nc;

    rv = io_submit(aio->aid, aio->ac, rlist);

    assert(rv >= 0);

    aio->nc -= rv;
}

int
lh_aio_reap(struct async_io *aio, struct aio_data **aio_d, int ac)
{
    struct iocb *acb;
    struct io_event io_e[MAX_AIO];
    struct timespec ts;

    int r;

    ts.tv_sec = 0;
    ts.tv_nsec = 0;

    r = io_getevents(aio->aid, 1, MAX_AIO, io_e, &ts);

    for (int i = 0 ; i < r; i++) {

        struct iocb* icb = (struct iocb*) io_e[i].obj;

        aio_d[i] = (struct aio_data *) icb->aio_data;
        aio_d[i]->pos += aio_d[i]->len;
    }

    return r;
}

#else
// #elif _freebsd_ __MACH__
#include <aio.h>
#include <sys/uio.h>

static int op_code[] = {0, LIO_READ, LIO_WRITE};

struct async_io *
aio_init(int pipe[2]) {
    struct async_io *aio;

    aio = (struct async_io *) calloc(1, sizeof(struct async_io));
    assert(aio);

    aio->alist = (struct aiocb *) calloc(MAX_AIO, sizeof(struct aiocb));
    aio->nlist = (struct aiocb *) calloc(MAX_AIO, sizeof(struct aiocb));

    memset(aio->alist, 0, sizeof(struct aiocb) * MAX_AIO);
    memset(aio->nlist, 0, sizeof(struct aiocb) * MAX_AIO);

    aio->ac = 0;

    return aio;
}

void
schedule_aio(struct async_io *aio, struct aio_data *aio_d, short filter)
{
    struct aiocb *acb = (struct aiocb *) aio->nlist;

    memset(&acb[aio->nc], 0, sizeof(struct aiocb));

    acb[aio->nc].aio_buf = aio_d->buf;
    acb[aio->nc].aio_nbytes = aio_d->len;
    acb[aio->nc].aio_offset = aio_d->pos;
    acb[aio->nc].aio_fildes = aio_d->fd;
    acb[aio->nc].aio_lio_opcode = op_code[filter];
    acb[aio->nc].aio_sigevent.sigev_value.sival_ptr = aio_d;

    aio->nc += 1;
}

void
lh_aio_schedule(struct async_io *aio, void *ctx)
{
    struct aiocb* rlist[MAX_AIO];
    struct aiocb* alist;
    struct sigevent se;
    int rv;

    memcpy(aio->alist, aio->nlist, sizeof(struct aiocb) * MAX_AIO);

    alist = (struct aiocb*) aio->alist;

    for (int i = 0; i < aio->nc; i++)
        rlist[i] = &alist[i];

    struct aiocb *acb_l = (struct aiocb *)aio->alist;

    aio->ac = aio->nc;

    memset(&se, 0, sizeof(struct sigevent));

    se.sigev_notify = SIGEV_SIGNAL;
    se.sigev_signo = SIGIO;
    se.sigev_value.sival_ptr = ctx;

    rv = lio_listio(LIO_NOWAIT, rlist, aio->ac, &se);

    if (rv < 0) {
        errno = 0;
        for (int i = 0; i < aio->ac; i++)  {
          int x = aio_error(&acb_l[i]);
          fprintf(stderr, "\nrv: %i, error: %s\n", x, (x > 0)? strerror(x): "-");
        }
    }

    assert(rv == 0);

    aio->nc = 0;
}

int
lh_aio_reap(struct async_io *aio, struct aio_data **aio_d, int ac)
{

    struct aiocb *acb = (struct aiocb *) aio->alist;
    int rv;

    for (int i = 0; i < ac; i++) {
        if (aio_error(&acb[i]) == 0) {
            rv = aio_return(&acb[i]);
            assert(rv >= 0);
            aio_d[i] = acb[i].aio_sigevent.sigev_value.sival_ptr;
            aio_d[i]->pos += rv;

        // some error
        } else
            aio_d[i]->len = -1;
    }
    return ac;
}

#endif
