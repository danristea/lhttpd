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

#ifndef _EVENT_H_
#define _EVENT_H_

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>

#include <assert.h>
#include <stdbool.h>
#include <fcntl.h>


// some system globals
#define NCPU 3  (sysconf(_SC_NPROCESSORS_ONLN))
#define MAX_KEV ((sysconf(_SC_OPEN_MAX)) * 2)

enum EV_FILTER {EV_SIGNAL = (0), EV_READ = (1) , EV_WRITE = (2)};

struct edata {
    short filter;
    int fd;
    void *ctx;
    void (*cb[3])(struct edata *ev);
};

struct equeue {
    int fd;
    int emax;
    unsigned long tv;
    int ce;
    int re;
    void *celist;
    void *relist;
};


struct equeue *equeue_init();
void equeue_add(struct equeue* eq, struct edata* ev, int fd, short filter, void *cb, void* ctx, short once);
void equeue_del(struct equeue* eq, struct edata* ev, int fd, short filter);
void equeue_poll(struct equeue* eq, int tv);

#define EQ_INIT() equeue_init()
#define EQ_ADD(eq, ev, fd, filter, cb, ctx, once) equeue_add(eq, ev, fd, filter, cb, ctx, once)
#define EQ_DEL(eq, ev, fd, filter) equeue_del(eq, ev, fd, filter)
#define EQ_POLL(eq, tv) equeue_poll(eq, tv)

#endif
