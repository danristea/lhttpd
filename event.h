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
