#include <signal.h>

#include "event.h"

extern void get_monotonic_time(struct timespec *ts);
static long ts_to_tv(struct timespec *ts);
struct timespec tv_to_ts(unsigned long tv);

// function that checks if fd is valid
int
fd_is_valid(int fd)
{
    return fcntl(fd, F_GETFD) != -1 || errno != EBADF;
}

// kqueue (bsd) specific event system code
#ifdef HAVE_SYS_EVENT_H
#include <sys/event.h>

static int ev_map[] = {EVFILT_SIGNAL, EVFILT_READ, EVFILT_WRITE};

struct equeue *
equeue_init()
{
    struct equeue *eq;

    eq = (struct equeue *) calloc(1, sizeof(struct equeue));
    assert(eq);

    eq->fd = kqueue();
    assert(eq->fd > -1);

    eq->relist = (struct kevent *) calloc((MAX_KEV), sizeof(struct kevent));
    assert(eq->relist);

    eq->celist = (struct kevent *) calloc((MAX_KEV * 2), sizeof(struct kevent));
    assert(eq->celist);

    eq->emax = (MAX_KEV * 2);

    return eq;
}

void
equeue_add(struct equeue *eq, struct edata *ev, int fd, short filter, void *cb, void *ctx, short once)
{
    struct kevent *ke;
    int rv;

    ke = (struct kevent*) eq->celist;

    // if event already exists inside kqueue, no need to re-add
    if (ev->filter & filter)
        return;

    // cleanup event struct not to pass garbage to kernel space
    memset(ke + eq->ce, 0, sizeof(ke));

    // populate the kernel event structure
    EV_SET(ke + eq->ce, fd, ev_map[filter], ((once == 1) ? (EV_ADD | EV_ENABLE | EV_ONESHOT) : EV_ADD), 0, 0, ev);

    ev->fd = fd;
    ev->filter |= filter;
    ev->ctx = ctx;
    ev->cb[filter] = cb;
    eq->ce++;
}

void
equeue_del(struct equeue *eq, struct edata *ev, int fd, short filter)
{
    struct kevent *ke;
    int rv;

    ke = (struct kevent*) eq->celist;

    // cleanup event struct not to pass garbage to kernel space
    memset(ke + eq->ec, 0, sizeof(ke));

    EV_SET(ke + eq->ce, fd, ev_map[filter], EV_DELETE, 0, 0, ev);

    ev->filter ^= filter;
    eq->ce++;
}

void
equeue_poll(struct equeue *eq, int tv)
{
    struct kevent *elist = eq->relist;
    struct timespec ts;
    struct edata *ev;
    int filter;
    int rv;
    int ce = 0;

    ce = eq->ce;
    eq->ce = 0;

    if (tv > -1) {
        ts = tv_to_ts((unsigned long)tv);
        rv = kevent(eq->fd, eq->celist, ce, eq->relist, MAX_KEV, &ts);
    } else
        rv = kevent(eq->fd, eq->celist, ce, eq->relist, MAX_KEV, NULL);

    if ((rv == -1) && (errno == EINTR || errno == EAGAIN))
        return;

    assert(rv > -1);
    get_monotonic_time(&ts);
    eq->tv = ts_to_tv(&ts);

    for (int i = 0; i < rv; i++) {

        ev = elist[i].udata;

        // currently not in use in favour of the self pipe trick
        if (elist[i].filter == EVFILT_SIGNAL) {
            ev->cb[EV_SIGNAL](ev);
            continue;
        }

        if ((elist[i].filter == EVFILT_READ) && (ev->filter & EV_READ)) {
            if (elist[i].flags & EV_ONESHOT)
                ev->filter ^= EV_READ;

            ev->cb[EV_READ](ev);
        }
        if ((elist[i].filter == EVFILT_WRITE) && (ev->filter & EV_WRITE)) {
            if (elist[i].flags & EV_ONESHOT)
                ev->filter ^= EV_WRITE;

            ev->cb[EV_WRITE](ev);
        }
    }
}

// epoll linux specific event system code
///////////////////////////////////////////////////////////////////////////////////////
#elif HAVE_SYS_EPOLL_H
#include <sys/epoll.h>

static int ev_map[] = {0, EPOLLIN, EPOLLOUT};
static int cdbg = 0;

struct equeue *
equeue_init()
{
    struct equeue* eq;

    eq = (struct equeue *) calloc(1, sizeof(struct equeue));
    assert(eq);

    eq->fd = epoll_create1(0);
    assert(eq->fd > -1);

    eq->celist = (struct epoll_event *) calloc((MAX_KEV * 2), sizeof(struct epoll_event));
    assert(eq->celist);

    eq->emax = MAX_KEV;
    eq->ce = 0;

    return eq;
}

void
equeue_add(struct equeue *eq, struct edata *ev, int fd, short filter, void *cb, void* ctx, short once)
{
    struct epoll_event ee;
    int rv;

    //if (ev->filter & filter) {
    if ((ev->filter & filter) && (once == 0)) {
        return;
    }

    memset(&ee, 0, sizeof(ee));

    ev->fd = fd;
    ee.data.ptr = ev;

    if ((ev->filter != 0) || ((ev->filter != 0) && (once == 1))) {
         ee.events = ev_map[ev->filter];
         ee.events |= ev_map[filter];

         if (once == 1) {
             ee.events |= EPOLLONESHOT | EPOLLET;
             ee.events |= EPOLLET;
          }

         rv = epoll_ctl(eq->fd, EPOLL_CTL_MOD, fd, &ee);
    } else {
        ee.events = ev_map[filter];

        if (once == 1) {
          ee.events |= EPOLLONESHOT | EPOLLET;
          ee.events |= EPOLLET;
        }

        rv = epoll_ctl(eq->fd, EPOLL_CTL_ADD, fd, &ee);
    }

    ev->filter |= filter;
    ev->ctx = ctx;
    ev->cb[filter] = cb;
    eq->ce++;
}

void
equeue_del(struct equeue *eq, struct edata *ev, int fd, short filter)
{
    struct epoll_event ee;
    int rv;

    memset(&ee, 0, sizeof(ee));

    ev->filter ^= filter;
    ee.data.ptr = ev;
    ee.events = ev_map[ev->filter];

    if (ee.events != 0)
        rv = epoll_ctl(eq->fd, EPOLL_CTL_MOD, fd, &ee);
    else
        rv = epoll_ctl(eq->fd, EPOLL_CTL_DEL, fd, &ee);

    assert(rv == 0);

    //ev->filter ^= filter;
    eq->ce--;
}

void
equeue_poll(struct equeue *eq, int tv)
{
    struct epoll_event *elist = eq->celist;
    struct timespec ts;
    struct edata *ev;
    int filter;
    int rv;

    rv = epoll_wait(eq->fd, elist, MAX_KEV, tv);

    if ((rv == -1) && (errno == EINTR || errno == EAGAIN))
        return;

    assert(rv > -1);
    get_monotonic_time(&ts);
    eq->tv = ts_to_tv(&ts);

    for (int i = 0; i < rv; i++) {
        ev = elist[i].data.ptr;

        if (((elist[i].events & EPOLLIN) || (elist[i].events & EPOLLHUP)) && (ev->filter & EV_READ)) {
              if (elist[i].events & EPOLLONESHOT) {
                  //ev->filter ^= EV_READ;
              }
              ev->cb[EV_READ](ev);
        }

        if (((elist[i].events & EPOLLOUT) || (elist[i].events & EPOLLHUP)) && (ev->filter & EV_WRITE)) {
              if (elist[i].events & EPOLLONESHOT) {
                  //ev->filter ^= EV_WRITE;
              }

              ev->cb[EV_WRITE](ev);
        }
    }
}

#endif

/////////////////////////////////////////////////////////////////////////////////////////

static long
ts_to_tv(struct timespec *ts)
{
    return (long)ts->tv_sec * 1000000000L + ts->tv_nsec;
};

struct timespec
tv_to_ts(unsigned long tv)
{
    return (struct timespec) {.tv_sec = tv / 1000, .tv_nsec = (tv % 1000) * 1000000};
};

//////////////////////////////////////////////////////////////////////////////////////////
