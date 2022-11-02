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
#include <signal.h>
#include <pthread.h>
#include <grp.h>

#include "httpd.h"

static void
sig_sigaction(int signo, siginfo_t *info, void* ctx)
{
    struct thread *thr = (struct thread *) info->si_value.sival_ptr;
    struct server *srv = thr->srv;
    uint64_t eval = 1;

	assert(write(thr->pfd[1], &eval, sizeof(eval)) == sizeof (eval));
}

static void
usage(struct server *srv)
{
    log_ex(NULL, 5, "usage: %s [-l lua prefix, lua script] [-c certifiate] [-k private key] [options]", srv->progname);
    log_ex(NULL, 5, "options:");
	log_ex(NULL, 5, "-l Lua prefix, Lua Script");
    log_ex(NULL, 5, "-u user");
    log_ex(NULL, 5, "-a address");
    log_ex(NULL, 5, "-p port");
    log_ex(NULL, 5, "-r rootdir");
	log_ex(NULL, 5, "-d (enable debuging)");
	log_ex(NULL, 5, "-f (foreground mode)");
    log_ex(srv, 1, "%s failed to start", srv->progname);
}

void
init(struct server *srv, config *cfg)
{
	struct thread thr;
    struct sigaction sigact;
	sigset_t set;
    struct passwd *pw;
    char addr[INET6_ADDRSTRLEN] = {'\0'};
	struct addrinfo h, *ai, *si;
    char buffer;
    int optval = 1;
	int rv;

	srv->conf = cfg;
	srv->timeout = 70;

	// ignore broken pipe and hangup signals
	memset(&sigact, 0, sizeof sigact);
	sigact.sa_handler = SIG_IGN;
	sigact.sa_flags = SA_RESTART;

	//	sigaction(SIGHUP, &sigact, NULL);
	sigaction(SIGPIPE, &sigact, NULL);

	// catch SIGIO to signal AIO completion
	memset(&sigact, 0, sizeof sigact);
	sigemptyset(&sigact.sa_mask);
	sigact.sa_flags = SA_SIGINFO;
	//sig_act.sa_flags = SA_RESTART | SA_SIGINFO;
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

	memset(&h, 0, sizeof h);

	h.ai_family = AF_UNSPEC; // use IPv4 or IPv6, whichever
	h.ai_flags = AI_PASSIVE; // use my IP
	h.ai_socktype = SOCK_STREAM;

	if ((rv = getaddrinfo(cfg->addr, "443", &h, &si)) != 0)
	    log_ex(srv, 1, "call to getaddrinfo failed (%s)", gai_strerror(rv));

	for (ai = si; ai != NULL; ai = ai->ai_next) {

		if ((srv->fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol)) <= -1) {
			log_ex(NULL, 5, "cannot create socket - %s", strerror(errno));
			continue;
		}

		if (setsockopt(srv->fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(int)) == -1)
			log_ex(srv, 0, "cannot reuse socket - %s", strerror(errno));

		if (fcntl(srv->fd, F_SETFL, fcntl(srv->fd, F_GETFL, 0) | O_NONBLOCK) < 0)
			log_ex(srv, 1, "cannot set non-blocking mode on server socket");

		if (bind(srv->fd, ai->ai_addr, ai->ai_addrlen) == -1) {
			close(srv->fd);
			log_ex(NULL, 5, "cannot bind PF_INET6 socket - %s", strerror(errno));
			continue;
		}
		break;
	}
	// free the server info addr struct
	freeaddrinfo(si);

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

	// initilize pthreads
    if ((srv->thr = calloc(NCPU, sizeof (struct thread))) == NULL)
        log_ex(srv, 1, "calloc thread - %s", strerror(errno));

    for (short i = 0; i < NCPU; i++) {

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

		// add the pipe to the event queue
		EQ_ADD(srv->thr[i].eq, &srv->thr[i].ev[1], srv->thr[i].pfd[0], EV_READ, thread_wakeup, &srv->thr[i], 0);

        if (pthread_create(&srv->thr[i].tid, NULL, serve, &srv->thr[i]))
            log_ex(srv, 1, "pthread_create - %s", strerror(errno));
     }
}

/* main */
int
main(int argc, char **argv)
{
    struct server* srv;
    struct config *cfg;
    int i;

	if (!((srv = calloc(1, sizeof(struct server))) && (cfg = calloc(1, sizeof(config)))))
	    log_ex(srv, 0, "error: memory allocation failure");

	if ((srv->progname = strrchr(argv[0], '/')) == NULL)
		srv->progname = e_strdup(argv[0]);
	else
		srv->progname++;

	cfg->addr = NULL;
	SIMPLEQ_INIT(&cfg->l_map);

    for (i = 1; i < argc; i++) {
	    if (strcmp(argv[i], "-u") == 0 && i + 1 < argc)
            cfg->user = e_strdup(argv[++i]);
        else if (strcmp(argv[i], "-r") == 0 && i + 1 < argc)
            cfg->rootdir = e_strdup(argv[++i]);
        else if (strcmp(argv[i], "-a") == 0 && i + 1 < argc)
            cfg->addr = e_strdup(argv[++i]);
        else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc)
            cfg->port = e_strdup(argv[++i]);
		else if (strcmp(argv[i], "-c") == 0)
			cfg->cert_file = e_strdup(argv[++i]);
		else if (strcmp(argv[i], "-k") == 0)
			cfg->pkey_file = e_strdup(argv[++i]);
        else if (strcmp(argv[i], "-d") == 0 && i + 1 < argc)
            cfg->debug = (int) strtol(argv[++i], (char **)NULL, 10);
        else if (strcmp(argv[i], "-f") == 0)
            cfg->fg = 1;
        else if (strcmp(argv[i], "-l") == 0 && i + 2 < argc) {

			if (*argv[i + 1] != '/')
		    	log_ex(srv, 1, "%s error: lua perfix path must start with /", srv->progname);

			lua_map *lm = malloc(sizeof(lua_map));

			lm->prefix = e_strdup(argv[++i]);
			lm->script = e_strdup(argv[++i]);
			SIMPLEQ_INSERT_TAIL(&cfg->l_map, lm, next);

		} else
            usage(srv);
    };

    if ((i <= 2) || SIMPLEQ_EMPTY(&cfg->l_map) || (!cfg->cert_file) || (!cfg->pkey_file))
        usage(srv);

    init(srv, cfg);

	for (i = 0; i < NCPU; i++)
		if (pthread_join(srv->thr[i].tid, NULL) != 0)
			log_ex(srv, 1, "pthread_join - %s", strerror(errno));

		/* TODO: cleanup, free, etc. */

    /* NOT REACHED */
    return (0);
};
