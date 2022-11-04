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

#ifndef _HTTPD_H_
#define _HTTPD_H_ 1

#ifndef SOFTWARE_NAME
#define SOFTWARE_NAME	"lhttpd"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <stddef.h>

#include <sys/socket.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>

#include "lua.h"
#include "event.h"
#include "httpd-aio.h"
#include "http.h"
#include "lauxlib.h"
#include "bearssl.h"
#include "brssl.h"
#include "hpack.h"

#define BUFFER_SIZE 4096
#define H2_HEADER_SIZE 9
#define H2_SETTINGS_FIELDS 6
#define H2_MAX_HEADER_FIELDS 64

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

enum io_state {
    IO_NONE = (0x0),
    IO_RECV = (0x1),
    IO_SEND = (0x2),
    IO_CLOSE = (0x6),
    IO_ERROR = (0x8),
    IO_WAIT = (0x10)
};

// BR_SSL_CLOSED    0x0001
// BR_SSL_SENDREC   0x0002
// BR_SSL_RECVREC   0x0004
// BR_SSL_SENDAPP   0x0008
// BR_SSL_RECVAPP   0x0010

typedef union {
    struct sockaddr		sa;
    struct sockaddr_in	sa4;
    struct sockaddr_in6	sa6;
} sock_addr;

typedef struct lua_map {
    const char 	*script;
    const char	*prefix;
    SIMPLEQ_ENTRY(lua_map) next;
} lua_map;

typedef struct config {
    char *port;
    double timeout;
    char *addr;
    char *user;
    char *rootdir;
    char *lua_prefix;
    char *lua_script;
    void *tls_config;
    char *cert_file;
    char *pkey_file;
    int debug;
    int fg;
    SIMPLEQ_HEAD(l_map, lua_map) l_map;
} config;

struct h2_settings {
    uint32_t header_table_size;
    uint32_t enable_push;
    uint32_t max_concurrent_streams;
    uint32_t window_size;
    uint32_t max_frame_size;
    uint32_t max_header_list_size;
};

struct h2_frame {
    uint32_t f_len;
    uint8_t f_typ;
    uint8_t f_flg;
    uint32_t f_sid;
};

struct frame_settings {
    uint8_t fh[H2_HEADER_SIZE];
    struct {
        uint16_t id;
        uint32_t val;
    } fields[];
};

typedef struct lua_handler {
    const char	*name;
    int		 ref;
    SIMPLEQ_ENTRY(lua_handler) next;
} lua_handler;

typedef struct lua_state_map {
    const char 	*script;
    const char	*prefix;
    lua_State	*L;
    SIMPLEQ_HEAD(l_hand, lua_handler) l_hand;
    SIMPLEQ_ENTRY(lua_state_map) next;
} lua_state_map;


typedef struct stream {
    int head;

    struct edata ev;
    enum io_state ss;

    lua_State* L;
    lua_State* T;
    struct connection *conn;

    int lua_status;

    size_t io_len;
    size_t io_idx;
    char *io_buf;

    //HTTP/2
    enum h2_stream_state h2_ss;
    enum h2_error h2_error;
    uint32_t h2_sid;
    int h2_dep;
    int h2_wgt;
    int h2_flg;
    int window_size;

    char *method;     //:method (HTTP/2)
    char *scheme;     //:scheme (HTTP/2)
    char *authority;  //:authority (HTTP/2)
    char *path;       //:path (HTTP/2)

    enum http_method http_method;
    int http_status;

    TAILQ_ENTRY(stream) link;
} stream;

struct thread {
    struct equeue *eq;
    pthread_t tid;
    int pfd[2];
    struct async_io *aio;
    struct edata ev[2];
    struct server *srv;
    struct connection *conn;

    SIMPLEQ_HEAD(L_map, lua_state_map) L_map;
    TAILQ_HEAD(conn, connection) conn_t;
};

struct server {
    struct edata ev;
    int fd;
    int ti;
    uintptr_t aid; // fd or signal for aio signaling
    sock_addr sa46;
    char *progname;
    char *pidfile;
    struct config *conf;
    long timeout;
    struct thread *thr;
    size_t cert_len;
    br_x509_certificate *cert;
    private_key *pkey;
};


typedef struct connection {

    struct edata ev;

    enum io_state cs;

    //struct active_state as;

    int fd;
    struct sockaddr_storage ss;

    long timestamp;
    struct thread* thr;

    struct stream *strm;

    int http_error;
    enum http_protocol http_protocol;
    char* protocol;

    int conn_close;
    int upgrade;

    char* buf;
    char rbuf[BUFFER_SIZE];
    size_t rlen;

    // ssl
    br_ssl_server_context ssl_sc;
    br_sslio_context ssl_ioc;
    unsigned ssl_state; //might not be necessary depending on implementation

    // HTTP/2
    struct h2_frame h2_frm;

    struct hpack_table *hpack_dec;
    struct hpack_table *hpack_enc;
    struct hpack_headerblock *hpack_hbd;
    struct hpack_headerblock *hpack_hbe;

/////////////////////////////////////////

    enum h2_state h2_state;
    struct h2_settings h2_set;
    enum h2_error h2_error;

    int cont_sid;
    int prom_sid;
    int f_len;
    int send_settings;
    int send_ping;
    char* ping_data;

    int h2_preface;
    int hs;
    uint32_t h_sid;

    int not_found;

    TAILQ_HEAD(strm, stream) strm_t;
    TAILQ_ENTRY(connection) link;
} connection;


//log.c
void log_init(char *progname, int dbg, int fg);
void log_ex(struct server *srv, int priority, const char *fmt, ...);
void log_dbg(int priority, const char *fmt, ...);

//time.c
void get_monotonic_time(struct timespec *ts);
void get_calendar_time(struct timespec *ts);
char* httpd_time(char *date, size_t datelen);
double get_elapsed_time(struct timespec *before, struct timespec *after);

//httpd-lua.c
int lua_map_create(struct thread*, struct l_map*);
static int register_handler(lua_State*);
struct lua_handler* find_handler(struct lua_state_map*, char*, char*);
void stack_dump(lua_State *L, const char *stackname);
int lev_read(struct stream* strm, char* buf, int len);
int lev_write(struct stream* strm, char* buf, int len);
int lua_run(lua_State *, lua_State *, int);
void lh_aio_dispatch(struct aio_data *aio_d);

// httpd-aio
void thread_wakeup(struct edata *ev);

//httpd.c
char* e_strdup(const char* oldstr);
void* serve(void *thread);
int new_conn(struct thread* thr);
void conntab_create(struct edata *ev);
void conn_io(struct connection *conn);

static long ts_to_tv(struct timespec* ts);
struct timespec tv_to_ts(unsigned long tv);

#endif
