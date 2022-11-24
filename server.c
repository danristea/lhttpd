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

#include <pwd.h>
#include <pthread.h>
#include <signal.h>
#include <grp.h>
#include <sys/types.h>

#include "httpd.h"


struct async_io **aio;

static void
sig_sigaction(int signo, siginfo_t *info, void *ctx)
{
    struct thread *thr = (struct thread *) (info->si_value.sival_ptr);
    uint64_t eval = 1;

#ifdef __APPLE__
    for (short i = 0; i < NCPU; i++) {
        if (aio[i]->wait == 1) {
            thr = (struct thread *) aio[i]->thr;
            assert(write(thr->pfd[1], &eval, sizeof(eval)) == sizeof (eval));
        }
    }
#else
    assert(write(thr->pfd[1], &eval, sizeof(eval)) == sizeof (eval));
#endif
}

void
signal_shutdown(struct server *srv)
{
    struct thread *thr;
    uint64_t eval = 0;

    for (short i = 0; i < NCPU; i++) {
        thr = &srv->thr[i];
        assert(write(thr->pfd[1], &eval, sizeof(eval)) == sizeof (eval));
    }
}

int
socket_bind4(struct sockaddr_in *ip4addr, unsigned short int sin_port)
{
    int optval = 1;
    int fd = -1;

    ip4addr->sin_family = AF_INET;
    ip4addr->sin_port = sin_port;

    if ((fd = socket(PF_INET, SOCK_STREAM, 0)) < 0)
        return -1;

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0)
        return -1;

    if (bind(fd, (struct sockaddr *)ip4addr, sizeof(struct sockaddr_in)) != 0)
        return -1;

    return fd;
}

int
socket_bind6(struct sockaddr_in6 *ip6addr, unsigned short int sin_port)
{
    int optval = 1;
    int fd = -1;

    ip6addr->sin6_family = AF_INET6;
    ip6addr->sin6_port = sin_port;

    if ((fd = socket(PF_INET6, SOCK_STREAM, 0)) < 0)
        return -1;

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0)
        return -1;

    if (bind(fd, (struct sockaddr *)ip6addr, sizeof(struct sockaddr_in6)) != 0)
        return -1;

    return fd;
}

void *
get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET)
        return &(((struct sockaddr_in *)sa)->sin_addr);

    return &(((struct sockaddr_in6 *)sa)->sin6_addr);
}

unsigned short int
get_in_port(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET)
        return ((struct sockaddr_in *)sa)->sin_port;

    return ((struct sockaddr_in6*)sa)->sin6_port;
}

void
init_run(struct server *srv)
{
    struct config *cfg = srv->conf;
    struct thread thr;
    struct sigaction sigact;
    sigset_t set;
    struct passwd *pw;
    char addr[INET6_ADDRSTRLEN] = {'\0'};
    uint16_t port;
    char buffer;
    int optval = 1;
    int rv;
    int i;

    srv->timeout = 30;

    // ignore broken pipe and hangup signals
    memset(&sigact, 0, sizeof sigact);
    sigact.sa_handler = SIG_IGN;
    sigact.sa_flags = SA_RESTART;

    //  sigaction(SIGHUP, &sigact, NULL);
    sigaction(SIGPIPE, &sigact, NULL);

    // catch SIGIO to signal AIO completion
    memset(&sigact, 0, sizeof sigact);
    sigemptyset(&sigact.sa_mask);
    sigact.sa_flags = SA_SIGINFO;
    sigact.sa_sigaction = sig_sigaction;
    sigaction(SIGIO, &sigact, NULL);

    if (!cfg->fg) {

        switch (fork()) {
            case -1:
                log_ex(srv, 1, "fork() - %s", strerror(errno));
            case 0:
                if (setsid() < 0)
                    log_ex(srv, 1, "setsid() - %s", strerror(errno));
                break;
            default:
                exit(1);

        }
        memset(&sigact, 0, sizeof sigact);
        sigact.sa_handler = SIG_IGN;
        sigact.sa_flags = SA_RESTART;
        sigaction(SIGINT, &sigact, NULL);
    }

    port = htons(strtol(cfg->port, (char **)NULL, 10));

    if (cfg->addr == NULL) {
        ((struct sockaddr_in *) &(srv->ss))->sin_addr.s_addr = INADDR_ANY;
        if ((srv->fd = socket_bind4((struct sockaddr_in *) &(srv->ss), port)) == -1) {
            ((struct sockaddr_in6 *) &(srv->ss))->sin6_addr = in6addr_any;
            if ((srv->fd = socket_bind6((struct sockaddr_in6 *) &(srv->ss), port)) == -1)
                log_ex(srv, 1, "cannot create and bind server socket");
        }
    } else if (strchr(cfg->addr, '.')) {
        inet_pton(AF_INET, cfg->addr, &((struct sockaddr_in *) &(srv->ss))->sin_addr);
        if ((srv->fd = socket_bind4(((struct sockaddr_in *) &(srv->ss)), port)) == -1)
            log_ex(srv, 1, "cannot create and bind ipv4 server socket");
    } else if (strchr(cfg->addr, ':')) {
        inet_pton(AF_INET6, cfg->addr, &((struct sockaddr_in6 *) &(srv->ss))->sin6_addr);
        if ((srv->fd = socket_bind6(((struct sockaddr_in6 *) &(srv->ss)), port)) == -1)
            log_ex(srv, 1, "cannot create and bind ipv6 server socket");
    } else
        log_ex(srv, 1, "invalid address");

    if (listen(srv->fd, SOMAXCONN) < 0)
        log_ex(srv, 1, "cannot listen on PF_INET6 socket - %s", strerror(errno));

    // read cert now if specified, before we chroot
    if (cfg->cert_file) {
        srv->cert = read_certificates(cfg->cert_file, &srv->cert_len);
        if (srv->cert == NULL || srv->cert_len == 0)
            log_ex(srv, 1, "certificate loading failed - %s", strerror(errno));
        srv->pkey = read_private_key(cfg->pkey_file);
        if (srv->pkey == NULL)
            log_ex(srv, 1, "private key loading failed - %s", strerror(errno));
    }

    // chroot to folder if specified
    if (cfg->rootdir) {
        if (chdir(cfg->rootdir) < 0)
            log_ex(srv, 1, "chdir(%s) - %s", cfg->rootdir, strerror(errno));
        if (chroot(cfg->rootdir) < 0)
            log_ex(srv, 0, "chroot(%s) - %s", cfg->rootdir, strerror(errno));
    }

    // drop privs to the runas user if specified
    if (cfg->user) {
        if ((pw = getpwnam(cfg->user)) == NULL)
            log_ex(srv, 1, "getpwnam - %s", strerror(errno));
        if (setgid(pw->pw_gid) < 0)
            log_ex(srv, 1, "setgid - %s", strerror(errno));
        if (initgroups(pw->pw_name, pw->pw_gid) < 0 )
            log_ex(NULL, 3, "initgroups - %s", strerror(errno));
        if (setuid(pw->pw_uid) < 0)
            log_ex(srv, 1, "setuid - %s",  strerror(errno));
    }

    // initialize logging
    log_init(srv->progname, cfg->debug, cfg->fg);

    // initialize hpack
    if (hpack_init() != 0)
        log_ex(srv, 1, "hpack init failure");

    // init aio
    aio = (struct async_io **) calloc(NCPU, sizeof(struct async_io *));

    // initilize pthreads
    if ((srv->thr = calloc(NCPU, sizeof (struct thread))) == NULL)
        log_ex(srv, 1, "calloc thread - %s", strerror(errno));

    for (i = 0; i < NCPU; i++) {

        srv->thr[i].srv = srv;

        SIMPLEQ_INIT(&srv->thr[i].L_map);
        TAILQ_INIT(&srv->thr[i].conn_t);

        if((new_conn(&srv->thr[i])) < 0)
            log_ex(srv, 1, "error preallocating connection - %s", strerror(errno));

        log_dbg(5, "->> thread %i equeue\n", i);
        if ((srv->thr[i].eq = EQ_INIT()) == NULL)
            log_ex(srv, 1, "error creating event queue - %s", strerror(errno));

        if (lua_map_create(&srv->thr[i], &cfg->l_map) < 0)
            log_ex(srv, 1, "error creating Lua map from script");

        // add the server socket to the first thread's event queue
        if (i == 0)
            EQ_ADD(srv->thr[i].eq, &srv->thr[i].ev[0], srv->fd, EV_READ, conntab_create, &srv->thr[i], ((NCPU == 1) ? 0: 1));

        // create a pipe and add it to the event queue for inter thread communication (self pipe trick)
        if (pipe(srv->thr[i].pfd) < 0)
            log_ex(srv, 1, "pipe - %s", strerror(errno));

        // make both ends of the pipe non-blocking
        if (fcntl(srv->thr[i].pfd[0], F_SETFL, fcntl(srv->thr[i].pfd[0], F_GETFL, 0) | O_NONBLOCK) < 0)
            log_ex(srv, 1, "cannot set non-blocking mode on pipe read fd");

        if (fcntl(srv->thr[i].pfd[1], F_SETFL, fcntl(srv->thr[i].pfd[1], F_GETFL, 0) | O_NONBLOCK) < 0)
            log_ex(srv, 1, "cannot set non-blocking mode on pipe write fd");

        // initialize async io
        if ((srv->thr[i].aio = AIO_INIT(srv->thr[i].pfd)) == NULL)
            log_ex(srv, 1, "error creating event queue - %s", strerror(errno));

        aio[i] = srv->thr[i].aio;
        aio[i]->thr = &srv->thr[i];

        // add the pipe to the event queue
        EQ_ADD(srv->thr[i].eq, &srv->thr[i].ev[1], srv->thr[i].pfd[0], EV_READ, thread_wakeup, &srv->thr[i], 0);

        if (pthread_create(&srv->thr[i].tid, NULL, serve, &srv->thr[i]))
            log_ex(srv, 1, "pthread_create - %s", strerror(errno));
    }

    for (i = 0; i < NCPU; i++)
        if (pthread_join(srv->thr[i].tid, NULL) != 0)
            log_ex(srv, 1, "pthread_join - %s", strerror(errno));
}

void *
serve(void *thread) {

    struct thread *thr = (struct thread *) thread;
    struct server *srv = thr->srv;
    struct equeue *eq = thr->eq;
    struct connection *conn;

    log_dbg(5, "%s: thread %p", __func__, thr);

    for (;;) {
//    while (!srv->err) {
        conn = TAILQ_FIRST(&thr->conn_t);

        EQ_POLL(eq, (conn ? (srv->timeout* 1000 - ((eq->tv - conn->timestamp)/1000000)): -1));

        if ((thr->aio->nc > 0) && (thr->aio->wait == 0))
            lh_aio_schedule(thr->aio, thread);

        while ((conn = TAILQ_FIRST(&thr->conn_t)) && ((eq->tv - (long)(srv->timeout*1000000000)) >= conn->timestamp))
            conntab_remove(conn);

        if (((conn = TAILQ_LAST(&thr->conn_t, conn)) == NULL) || (conn->fd != -1)) {
            if ((new_conn(thr)) < 0)
                log_ex(srv, 1, "%s: (error preallocating connection: %s)", __func__, strerror(errno));
        }
    }
    return NULL;
}

void
cleanup(struct server *srv)
{
    struct config *cfg = srv->conf;
    struct thread *thr;
    lua_state_map *Lm, *tLm;
    lua_map *lm, *tlm;
    lua_handler *lh, *tlh;
    connection *conn, *tconn;

    if (cfg->user)
        free(cfg->user);

    if (cfg->rootdir)
        free(cfg->rootdir);

    free(cfg->addr);
    free(cfg->port);
    free(cfg->cert_file);
    free(cfg->pkey_file);

    free(aio);

    SIMPLEQ_FOREACH_SAFE(lm, &cfg->l_map, link, tlm) {
        free((void *)lm->script);
        free((void *)lm->prefix);
        free(lm);
    }

    for (int i = 0; i < NCPU; i++) {
        thr = &srv->thr[i];

        SIMPLEQ_FOREACH_SAFE(Lm, &thr->L_map, link, tLm) {
            SIMPLEQ_FOREACH_SAFE(lh, &Lm->l_hand, link, tlh) {
                free((void *)lh->name);
                free(lh);
            }
            lua_close(Lm->L);
            free(Lm);
        }

        TAILQ_FOREACH_SAFE(conn, &thr->conn_t, link, tconn)
            conntab_remove(conn);

        free(thr->eq);
        free(thr->aio);
    }
    free(srv->thr);

    free_certificates(srv->cert, srv->cert_len);
    free_private_key(srv->pkey);

    free(srv->progname);

    free(srv);
}

void
thread_wakeup(struct edata *ev)
{
    struct thread *thr = (struct thread *) ev->ctx;
    struct server *srv = thr->srv;
    int ac = thr->aio->ac;
    char c;
    int id = -1;
    uint64_t ne = 0;
    int rv;

    log_dbg(5, "%s: ev %p", __func__, ev);

    if (ev->filter != 0) {
        rv = read(ev->fd, &ne, sizeof(ne));
        if (rv != sizeof (ne)) {
            log_dbg(2, "%s: thread signaling error", __func__);
            // should we terminate?
            return;
        }
        if (ne == 0)
            pthread_exit((void *) -1);
    }

    if ((thr->aio->wait == 1) && (ne > 0)) {
        while (ac > 0) {
            struct aio_data *aio_d[MAX_AIO];

            thr->aio->wait = 0;
            int n = thr->aio->ac;
            thr->aio->ac = 0;

            int r;

            r = lh_aio_reap(thr->aio, aio_d, ac);

            if (r <= 0)
                break;

            for (int i = 0; i < r; i++)
                lh_aio_dispatch(aio_d[i]);

            ac -= r;
            thr->aio->ac = ac;
        }
    }
}
