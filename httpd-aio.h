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

#ifndef _HTTPD_AIO_
#define _HTTPD_AIO_

#include "event.h"
#include "queue.h"


#define MAX_AIO (_SC_AIO_MAX)
#define MAX_LISTIO (sysconf(_SC_AIO_LISTIO_MAX))

typedef struct aio_data {
    int fd;
    char *buf;
    size_t len;
    long pos;
    off_t flen;
    void *ctx;
} aio_data;

struct async_io {
    long aid;
    void *sigd;
    int ac;
    int nc;
    int wait;
    int ready;
    void *nlist;
    void *alist;
    void *thr;
};


struct async_io *aio_init(int pipe[2]);
void schedule_aio(struct async_io *, struct aio_data *, short);
void lh_aio_schedule(struct async_io *, void *);
int lh_aio_reap(struct async_io *, struct aio_data **, int);

#define AIO_INIT(pipe) aio_init(pipe)

#endif
