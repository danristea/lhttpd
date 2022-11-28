/*
BSD 2-Clause License

Copyright (c) 2022, Daniel Ristea <daniel.ristea@outlook.com>
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

#include <grp.h>

#include "httpd.h"

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

/* main */
int
main(int argc, char **argv)
{
    struct server *srv;
    struct config *cfg;
    int i;

    if (!((srv = calloc(1, sizeof(struct server))) && (cfg = calloc(1, sizeof(config)))))
        log_ex(srv, 0, "error: memory allocation failure");

    srv->conf = cfg;

    if ((srv->progname = strrchr(argv[0], '/')) == NULL)
        srv->progname = e_strdup(argv[0]);
    else
        srv->progname = e_strdup(++srv->progname);

    cfg->addr = NULL;
    cfg->port = NULL;
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
            SIMPLEQ_INSERT_TAIL(&cfg->l_map, lm, link);

        } else
            usage(srv);
    };

    if ((i <= 2) || SIMPLEQ_EMPTY(&cfg->l_map) || (!cfg->cert_file) || (!cfg->pkey_file))
        usage(srv);

    init_run(srv);

    /* cleanup, free, etc. */
    cleanup(srv);

    return (0);
};
