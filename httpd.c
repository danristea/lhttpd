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

#include <fcntl.h>
#include <ctype.h>
#include <dirent.h>
#include <sys/stat.h>

#include "httpd.h"

#if !(SERVER_RSA || SERVER_EC || SERVER_MIXED)
#define SERVER_RSA     1
#define SERVER_EC      0
#define SERVER_MIXED   0
#endif

#define INIT_HB_BUF_SIZE (1 << 13)

extern struct async_io **aio;

static const char* http_protocols[] = HTTP_PROTOCOLS;
const char *proto_name = "h2";

// default http/2 settings
struct h2_settings h2_settings = {
    .header_table_size = 4096,
    .enable_push = 1,
    .max_concurrent_streams = 1,
    .window_size = 65535,
    .max_frame_size = 16384,
    .max_header_list_size = 0xFFFFFFFF
};

static void strdecode(char *str);

void conn_io(struct connection *conn);
void conn_read(struct edata *ev);
void conn_write(struct edata *ev);

void app_send(struct connection *conn);
void app_recv(struct connection *conn);

static void
sig_sigaction(int signo, siginfo_t *info, void *ctx)
{
    struct thread *thr = (struct thread *) (info->si_value.sival_ptr);
    uint64_t eval = 1;

    log_dbg(5, "########## ->>>>> ctx %p thr %p", ctx, thr);

#ifndef __APPLE__
    assert(write(thr->pfd[1], &eval, sizeof(eval)) == sizeof (eval));
#else
    for (short i = 0; i < NCPU; i++) {
        fprintf(stderr, "\nCALLING ADDRESS %p     wait is %i     nc %i ac %i", aio[i], aio[i]->wait, aio[i]->nc, aio[i]->ac);
        if (aio[i]->wait == 1) {
//        if (aio[i]->ac > 0) {
//          if ((aio[i]->wait == 1) || ((aio[i]->ac == aio[i]->nc) && (aio[i]->ac > 0))) {
//          if ((aio[i]->wait == 1) && (aio[i]->ac > 0)) {
            //if (aio_return(aio[i]->alist) >= 0) {
                struct thread *thr = (struct thread *) aio[i]->thr;
                assert(write(thr->pfd[1], &eval, sizeof(eval)) == sizeof (eval));
                log_dbg(5, "wrote on thr thr %p", thr);

            //}
        }
    }
#endif
}

char *
strnstr(const char *s, const char *find, size_t slen)
{
    char c, sc;
    size_t len;

    if ((c = *find++) != '\0') {
        len = strlen(find);
        do {
            do {
                if (slen-- < 1 || (sc = *s++) == '\0')
                    return (NULL);
            } while (sc != c);
            if (len > slen)
                return (NULL);
        } while (strncmp(s, find, len) != 0);
        s--;
    }
    return ((char *)s);
}

int
check_request(const char *buf, int len)
{
    char *c;

    if ((c = strnstr(buf, "\r\n\r\n", len)))
        return ((c - buf) + 4);
    if ((c = strnstr(buf, "\n\n", len)))
        return ((c - buf) + 2);

    return 0;
}

static void
strdecode(char *str)
{
    for (char *from = str ; *from != '\0'; ++str, ++from ) {
        if ( from[0] == '%' && isxdigit( from[1] ) && isxdigit( from[2] ) ) {
            char buf[] = {from[1], from[2], '\0'};
            *str = (char)strtol(buf, NULL, 16);
            from += 2;
        } else
            *str = *from;
    }
    *str = '\0';
}

static void
strencode(char *to, int tosize, char *from)
{
    int tolen;

    for (tolen = 0; *from != '\0' && tolen + 4 < tosize; ++from) {
        if (isalnum(*from) || strchr( "/_.-~", *from ) != (char*) 0) {
            *to = *from;
            ++to;
            ++tolen;
        } else {
            (void) sprintf( to, "%%%02x", (int) *from & 0xff );
            to += 3;
            tolen += 3;
        }
    }
    *to = '\0';
}

void
pack_uint32(uint8_t *buf, uint32_t n)
{
    buf[3] = n & 0xFF;
    buf[2] = (n >> 8) & 0xFF;
    buf[1] = (n >> 16) & 0xFF;
    buf[0] = (n >> 24) & 0x7F;
}

// initialize http/2 specifics: hpack, settings, states
int
h2_init(struct connection *conn)
{
    log_dbg(5, "%s: conn %p", __func__, conn);

    if ((conn->hpack_dec = hpack_table_new((size_t) h2_settings.header_table_size)) == NULL)
        goto err;

    if ((conn->hpack_enc = hpack_table_new((size_t) h2_settings.header_table_size)) == NULL)
        goto err;

    if ((conn->hpack_hbd = hpack_headerblock_new()) == NULL)
        goto err;

    conn->http_protocol = HTTP2;
    conn->h2_state = H2_WAITING_MAGIC;
    conn->h2_set = h2_settings;
    conn->h2_preface = 1;

    conn->cs |= IO_SEND;

    return 0;

err:
    log_dbg(5, "%s: conn %p hpack allocation failure \n", __func__, conn);
    conn->cs = IO_ERROR;
    return -1;
}

void
strmtab_remove(struct stream *strm)
{
    struct connection *conn = strm->conn;
    struct stream *sp;
    lua_State *L;
    lua_State *T;

    log_dbg(5, "%s: strm %p", __func__, strm);

    L = strm->L;
    T = strm->T;

    strm->ss = 0;
    TAILQ_REMOVE(&conn->strm_t, strm, link);

    lua_pushthread(strm->T);
    lua_pushnil(strm->T);
    lua_rawset(strm->T, LUA_REGISTRYINDEX);

    lua_gc(L, LUA_GCCOLLECT, 0);

    if (strm == conn->strm)
        conn->strm = NULL;

    strm = NULL;
}


struct stream*
h2_find_stream(struct connection *conn, uint32_t h2_sid)
{
    struct stream *strm;

    TAILQ_FOREACH(strm, &conn->strm_t, link) {
        if (h2_sid == strm->h2_sid)
            return strm;
    }
    return NULL;
}

void
pack_frame_header(uint8_t *buf, uint32_t len, uint8_t flg, uint8_t typ, uint32_t sid)
{
    log_dbg(5, "%s: buf %p len %i flg %i typ %i sid %i\n", __func__, buf, len, flg, typ, sid);

    buf[2] = len & 0xFF;
    buf[1] = (len >> 8) & 0xFF;
    buf[0] = (len >> 16) & 0xFF;
    buf[3] = typ;
    buf[4] = flg;

    pack_uint32(&buf[5], sid);
}

char *
status_msg(int code, int *len)
{
    struct {
        short code;
        char *msg;
    } http_status[] = HTTP_STATUS;

    for (int i = 0; http_status[i].msg != NULL; i++) {
        if (code == http_status[i].code) {
            *len = strlen(http_status[i].msg);
            return http_status[i].msg;
        }
    }

    return NULL;
}

struct stream *
start_lua(struct connection *conn, struct L_map *L_map, char *path)
{
    struct sockaddr *server_ss = (struct sockaddr *)&conn->thr->srv->ss;
    struct sockaddr *client_ss = (struct sockaddr *)&conn->ss;
    struct stream *strm = NULL;
    struct lua_state_map *Lm;
    struct lua_handler *lh;
    lua_State *T;
    char addr[INET6_ADDRSTRLEN];
    char date[40];
    char *prefix;
    char *handler;
    char *query = NULL;
    int port;
    int len;

    log_dbg(5, "%s: conn %p L_map %p path %s", __func__, conn, L_map, path);

    // get the query from path
    if ((query = strchr(path, '?')) != NULL)
        query++;

    prefix = path;

    while ((*prefix == '/') && (*(prefix + 1) == '/'))
        prefix++;

    if ((handler = strchr(prefix + 1, '/')) != NULL) {
        len = handler - prefix;
    } else {
        handler = prefix;
        len = 1;
    }

    // loop through lua map states
    SIMPLEQ_FOREACH(Lm, L_map, link) {

        if ((strncmp(prefix, Lm->prefix, len)) || (len != strlen(Lm->prefix)))
            continue;

        // try to find handler
        lh = find_handler(Lm, handler, query);

        // if handler not found, see if we have a notfound fallback
        if (lh == NULL) {
            lh = find_handler(Lm, "/notfound", NULL);

            if (lh == NULL)
                break;
        }

        T = lua_newthread(Lm->L);

        if (T == NULL) {
            conn->http_error = 500;
            return NULL;
        }

        lua_pushthread(T);
        strm = (struct stream *) lua_newuserdata(T, sizeof(struct stream));
        lua_rawset(T, LUA_REGISTRYINDEX);

        lua_pop(Lm->L, 1);

        lua_rawgeti(T, LUA_REGISTRYINDEX, lh->ref);

        memset(strm, 0, sizeof(struct stream));

        strm->T = T;
        strm->L = Lm->L;
        strm->conn = conn;
        conn->strm = strm;

        lua_newtable(T);
        lua_pushstring(T, SOFTWARE_NAME);
        lua_setfield(T, -2, "SERVER_SOFTWARE");
        lua_pushstring(T, http_protocols[conn->http_protocol]);
        lua_setfield(T, -2, "SERVER_PROTOCOL");
        lua_pushstring(T, Lm->script);
        lua_setfield(T, -2, "SCRIPT_FILENAME");
        lua_pushstring(T, Lm->prefix);
        lua_setfield(T, -2, "SCRIPT_PREFIX");
        lua_pushstring(T, lh->name);
        lua_setfield(T, -2, "HANDLER_NAME");

        lua_pushinteger(T, ntohs(get_in_port((struct sockaddr *) &conn->thr->srv->ss)));
        lua_setfield(T, -2, "SERVER_PORT");

        inet_ntop(server_ss->sa_family, get_in_addr(server_ss), addr, INET6_ADDRSTRLEN);
        lua_pushstring(T, addr);
        lua_setfield(T, -2, "SERVER_ADDR");

        lua_pushinteger(T, ntohs(get_in_port((struct sockaddr *) &conn->ss)));
        lua_setfield(T, -2, "CLIENT_PORT");

        inet_ntop(client_ss->sa_family, get_in_addr(client_ss), addr, INET6_ADDRSTRLEN);
        lua_pushstring(T, addr);
        lua_setfield(T, -2, "CLIENT_ADDR");

        if (query != NULL) {
            lua_pushstring(T, query);
            lua_setfield(T, -2, "QUERY_INFO");
        }

        lua_pushstring(T, httpd_time(date, sizeof date));
        lua_setfield(T, -2, "DATE_UTC");

        lua_pushinteger(T, conn->h2_set.enable_push);
        lua_setfield(T, -2, "PUSH_PROMISE");

        // headers
        lua_newtable(T);

        strm->T = T;
        TAILQ_INSERT_TAIL(&conn->strm_t , strm, link);
        return strm;
    }

    conn->http_error = 404;
    return NULL;
}


// write http/2 header with information retrieved from the lua header table
int
http2_header(struct stream *strm, char *buf, int len)
{
    struct connection *conn = strm->conn;
    lua_State *T = strm->T;
    uint32_t f_sid = 0;
    uint8_t f_typ;
    int offset = 0;
    int status;
    char const *key;
    char const *val;
    struct stream *pstrm = NULL;
    unsigned char *enc_b;
    size_t enc_l;

    log_dbg(5, "%s: strm %p buf %p len %i", __func__, strm, buf, len);

    memset(buf, 0, (sizeof (uint8_t) * (H2_HEADER_SIZE + 4)));
    conn->hpack_hbe = hpack_headerblock_new();

    // check if the stream has an error, write default error response
    if (strm->h2_error > 0)
        goto err;

    // check if lua header function argument is a table and write error response otherwise
    if (lua_type(T, 1) != LUA_TTABLE) {
        log_dbg(5, "httpd.header: function argument not a lua table");
        goto err;
    }

    // check type of header (response/promise) by searching for :status pseudo header
    lua_getfield(T, 1, ":status");

    // check if found and process it as a response header
    if (lua_type(T, 2) == LUA_TSTRING) {
        f_typ = HEADERS;
        f_sid = strm->h2_sid;

        val = luaL_checkstring(T, 2);
        lua_pop(T, 1);

        // throw error if we can't get the :status pseudo header
        if (val == NULL)
            goto err;

        // add status header field to the hpack header structure
        if (hpack_header_add(conn->hpack_hbe, ":status", val, 0) == NULL)
            goto err;

        // convert it to a number to check the status code value aritmetically
        status = strtol(val, (char **)NULL, 10);

        // check if the conversion was successful
        if ((status < INT_MIN) || (status > INT_MAX))
            goto err;

        // check the status code value and change the stream status accordingly
        if ((status < 100) || (status >= 400))
            strm->h2_ss = SS_HCLOSED_LOCAL;

    // otherwise process it as a promise header
    } else {
        struct connection *conn = strm->conn;
        struct stream* pstrm;
        uint32_t psid;

        offset = 4;

        lua_pop(T, 1);

        f_typ = PUSH_PROMISE;

        lua_getfield(T, 1, ":method");

        if (lua_isnil(T, 2)) {
            lua_pop(T, 1);
            strm->http_status = 500;
            goto err;
        }

        val = luaL_checkstring(T, 2);
        if (hpack_header_add(conn->hpack_hbe, ":method", val, 0) == NULL)
            goto err;

        lua_pop(T, 1);

        lua_getfield(T, 1, ":authority");
        val = luaL_checkstring(T, 2);
        if (hpack_header_add(conn->hpack_hbe, ":authority", val, 0) == NULL)
            goto err;
        lua_pop(T, 1);

        lua_getfield(T, 1, ":scheme");
        val = luaL_checkstring(T, 2);
        if (hpack_header_add(conn->hpack_hbe, ":scheme", val, 0) == NULL)
            goto err;
        lua_pop(T, 1);

        lua_getfield(T, 1, ":path");
        val = luaL_checkstring(T, 2);
        if (hpack_header_add(conn->hpack_hbe, ":path", val, 0) == NULL)
            goto err;
        lua_pop(T, 1);

        if ((conn->prom_sid == 0) || (strm->h2_sid > conn->prom_sid))
            conn->prom_sid = strm->h2_sid + 1;
        else
            conn->prom_sid  += 2;

        psid = (uint32_t) conn->prom_sid;

        *(buf + 12) = psid & 0xFF;
        *(buf + 11) = (psid >> 8) & 0xFF;
        *(buf + 10) = (psid >> 16) & 0xFF;

        if ((pstrm = start_lua(conn, &conn->thr->L_map, (char *)val)) == NULL)
            goto err;

        pstrm->h2_sid = conn->prom_sid;
        pstrm->h2_ss = SS_RESERVED_LOCAL;

        if ((pstrm->lua_status = lua_run(pstrm->T, pstrm->L, 2)) > LUA_YIELD) {
            log_dbg(5, "error calling Lua handler");
            goto err;
        }
    }

    // add remaining header fields to the hpack header structure
    lua_pushnil(T);
    while(lua_next(T, -2)) {
        key = lua_tostring(T, -2);
        val = lua_tostring(T, -1);

        // exclude pseudo headers (headers that starts with ":")
        if ((strncmp(key, ":", 1) != 0) && (f_typ == HEADERS))
            if (hpack_header_add(conn->hpack_hbe, key, val, 0) == NULL)
                goto err;

        lua_pop(T, 1);
    }

    if ((enc_b = hpack_encode(conn->hpack_hbe, &enc_l, conn->hpack_enc)) == NULL) {
        log_dbg(5, "hpack encoding error");
        goto err;
    }

    memcpy(buf + (sizeof(uint8_t) * H2_HEADER_SIZE + offset), enc_b, enc_l);

    hpack_headerblock_free(conn->hpack_hbe);

    uint8_t flags = 0;
    flags |= FF_END_HEADERS;

    pack_frame_header((uint8_t *)buf, enc_l + offset, flags, f_typ, strm->h2_sid);

    strm->head = 0;

    // return total size written frame (header + payload)
    return (H2_HEADER_SIZE + enc_l + offset);

err:
    hpack_headerblock_free(conn->hpack_hbe);
    return -1;
}

char *
e_strdup(const char *str)
{
    char* dup = strdup(str);
    if (dup == NULL)
        log_ex(NULL, 1, "%s: %s", __func__, strerror(errno));
    return dup;
}

int
new_conn(struct thread *thr)
{
    struct server *srv = thr->srv;
    connection *conn;
    struct stream *strm;
    int len;

    log_dbg(5, "%s: thr %p", __func__, thr);

    // alloc memory for new connection
    if ((conn = calloc(1, sizeof(connection))) == NULL)
        return -1;

    TAILQ_INIT(&conn->strm_t);

    conn->fd = -1;
    conn->strm = NULL;

    conn->thr = thr;
    thr->conn = conn;

    if ((conn->buf = malloc(sizeof(char) * (BR_SSL_BUFSIZE_BIDI + 1))) == NULL)
        return -1;

    br_ssl_server_zero(&conn->ssl_sc);

#if SERVER_RSA
#if SERVER_PROFILE_MIN_FS
#if SERVER_CHACHA20
    br_ssl_server_init_mine2c(&conn->ssl_sc, srv->cert, srv->cert_len, &srv->pkey->key.rsa);
#else
    br_ssl_server_init_mine2g(&conn->ssl_sc, srv->cert, srv->cert_len, &srv->pkey->key.rsa);
#endif
#elif SERVER_PROFILE_MIN_NOFS
    br_ssl_server_init_minr2g(&conn->ssl_sc, srv->cert, srv->cert_len, &srv->pkey->key.rsa);
#else
    br_ssl_server_init_full_rsa(&conn->ssl_sc, srv->cert, srv->cert_len, &srv->pkey->key.rsa);
#endif
#elif SERVER_EC
#if SERVER_PROFILE_MIN_FS
#if SERVER_CHACHA20
    br_ssl_server_init_minf2c(&conn->ssl_sc, srv->cert, srv->cert_len, &srv->pkey->key.ec);
#else
    br_ssl_server_init_minf2g(&conn->ssl_sc, srv->cert, srv->cert_len, &srv->pkey->key.ec);
#endif
#elif SERVER_PROFILE_MIN_NOFS
    br_ssl_server_init_minv2g(&conn->ssl_sc, srv->cert, srv->cert_len, &srv->pkey->key.ec);
#else
    br_ssl_server_init_full_ec(&conn->ssl_sc, srv->cert, srv->cert_len, BR_KEYTYPE_EC, &srv->pkey->key.ec);
#endif
#else
#if SERVER_PROFILE_MIN_FS
#if SERVER_CHACHA20
    br_ssl_server_init_minf2c(&conn->ssl_sc, srv->cert, srv->cert_len, &srv->pkey->key.ec);
#else
    br_ssl_server_init_minf2g(&conn->ssl_sc, srv->cert, srv->cert_len, &srv->pkey->key.ec);
#endif
#elif SERVER_PROFILE_MIN_NOFS
    br_ssl_server_init_minu2g(&conn->ssl_sc, srv->cert, srv->cert_len, &srv->pkey->key.ec);
#else
    br_ssl_server_init_full_ec(&conn->ssl_sc, srv->cert, srv->cert_len, BR_KEYTYPE_RSA, &srv->pkey->key.ec);
#endif
#endif

    br_ssl_engine_set_protocol_names(&conn->ssl_sc.eng, &proto_name , 1);
    br_ssl_engine_set_buffer(&conn->ssl_sc.eng, conn->buf, BR_SSL_BUFSIZE_BIDI, 1);

    return 0;
};

void
conntab_update(struct connection *conn)
{
    struct thread *thr = conn->thr;

    log_dbg(5, "%s: conn %p timer: %i \n", __func__, conn, thr->eq->tv);

    TAILQ_REMOVE(&thr->conn_t, conn, link);
    TAILQ_INSERT_TAIL(&thr->conn_t, conn, link);

    conn->timestamp = thr->eq->tv;
}

void
conntab_remove(struct connection *conn)
{
    struct thread *thr = conn->thr;
    struct lua_state_map *Lmap;

    if (conn == NULL)
        return;

    log_dbg(5, "%s: conn %p fd: %i", __func__, conn, conn->fd);

    //if (conn->ev.filter & EV_READ)
    //    EQ_DEL(conn->thr->eq, &conn->ev, conn->fd, EV_READ);

    //if (conn->ev.filter & EV_WRITE)
    //    EQ_DEL(conn->thr->eq, &conn->ev, conn->fd, EV_WRITE);

    conn->ev.filter = 0;

    close(conn->fd);

    if (thr->srv->cert_len > 0)
        br_ssl_engine_flush(&conn->ssl_sc.eng, 0);

    free(conn->buf);

    if (conn->http_protocol == HTTP/2) {
        hpack_table_free(conn->hpack_enc);
        hpack_table_free(conn->hpack_dec);
        hpack_headerblock_free(conn->hpack_hbd);
        hpack_headerblock_free(conn->hpack_hbe);
    }

    TAILQ_REMOVE(&thr->conn_t, conn, link);

    free(conn);
    conn = NULL;
}

void
conntab_create(struct edata *ev)
{
    struct thread *thr = ev->ctx;
    struct connection *conn = thr->conn;
    struct server *srv = thr->srv;
    socklen_t len = sizeof(struct sockaddr_storage);
    int ovtval = 1;
    char c;

    log_dbg(5, "%s: ev %p", __func__, ev);

    // new connection event fired, ream in a different thread and signal it via pipe
    if (NCPU > 1) {

        if ((srv->ti += 1) >= NCPU)
            srv->ti = 0;

        EQ_ADD(srv->thr[srv->ti].eq, &srv->thr[srv->ti].ev[0], srv->fd, EV_READ, conntab_create, &srv->thr[srv->ti], 1);

        uint64_t eval = 1;
        assert(write(srv->thr[srv->ti].pfd[1], &eval, sizeof(eval)) == sizeof (eval));
    }

    if ((conn->fd = accept(srv->fd, (struct sockaddr *)&(conn->ss), &len)) == -1) {
        if (!(errno == EINTR || errno == ECONNABORTED))
            log_ex(NULL, 5, "accept error - %s", strerror(errno));
        return;
    }

    log_dbg(5, "%s: conn %p fd %i", __func__, conn, conn->fd);

    fcntl(conn->fd, F_SETFL, fcntl(conn->fd, F_GETFL, 0) | O_NONBLOCK);

    TAILQ_INSERT_TAIL(&thr->conn_t, conn, link);

    conn->timestamp = thr->eq->tv;

    conn->cs = IO_RECV;

    conntab_update(conn);

    br_ssl_server_reset(&conn->ssl_sc);

    return conn_io(conn);
}




int
parse_http(struct connection *conn, char *buf, int len)
{
    struct stream *strm = NULL;
    struct lua_handler *lh;
    int idx = 0;
    char *c;

    log_dbg(5, "%s: buf %p len %i", __func__, buf, len);

    while ((c = memchr(buf, '\n', len - idx)) != NULL) {

        idx = (c - buf) + 1;

        *c = '\0';

        if (*(c-1) == '\r')
            *(c-1) = '\0';

        if (strm == NULL) {
            char *method;
            char *proto;
            char *path;

            if (c - buf < 1)
                break;

            method = buf;
            method += strspn(method, " \t");

            if ((path = strpbrk(method, " \t")) == NULL)
                break;

            *path++ = '\0';
            path += strspn(path, " \t");

            while (path[1] == '/')
                path++;

            if (path >= c - 1)
                break;

            if ((proto = strpbrk(path, " \t")) == NULL)
                break;

            *proto++ = '\0';
            proto += strspn(proto, " \t");

            if (strcasecmp(proto, "HTTP/1.1") == 0) {
                conn->http_protocol = HTTP11;
            } else if (strcasecmp(proto, "HTTP/1.0") == 0)
                conn->http_protocol = HTTP10;
            else {
                log_dbg(5, "%s: (unknown protocol)", __func__);
                break;
            }

            strdecode(path);

            strm = start_lua(conn, &conn->thr->L_map, path);

            if (strm == NULL)
                return -1;

            if (strcasecmp(method, "HEAD") == 0) {
                strm->http_method = HEAD;
            } else if (strcasecmp(method, "GET") == 0) {
                strm->http_method = GET;
            } else if (strcasecmp(method, "POST") == 0) {
                strm->http_method = POST;
            } else {
                log_dbg(5, "%s: (unsupported method)", __func__);
                //break;
            }

            lua_pushstring(strm->T, "method");
            lua_pushstring(strm->T, method);
            lua_settable(strm->T, -3);

            lua_pushstring(strm->T, "path");
            lua_pushstring(strm->T, path);
            lua_settable(strm->T, -3);

        } else {
            char *key;
            char *val;

            // check if the request is done
            if (c - buf <= 1) {
                if ((strm->lua_status = lua_run(strm->T, strm->L, 2)) > LUA_YIELD) {
                    log_dbg(5, "%s: (error calling Lua handler)", __func__);
                    conn->http_error = 500;
                    return -1;
                }
                return 0;
            }

            key = buf;
            key += strspn(key, " \t");

            if (((val = strchr(key, ':')) == NULL) || (val == key))
                break;

            *val++ = '\0';
            val += strspn(val, " \t");

            if (strcasecmp(key, "connection") == 0 && strcasecmp(val, "close") == 0)
                conn->conn_close = 1;

            lua_pushstring(strm->T, val);
            lua_setfield(strm->T, -2, key);

#if 0
            else if (strcasecmp(key, "connection") == 0 && strcasecmp(val, "upgrade") == 0)
                conn->upgrade = 1;
            else if (strcasecmp(key, "upgrade") == 0 && strcasecmp(val, "h2c") == 0) {
                break;
            }
#endif
            log_dbg(5, "%s: (adding header# %s: %s)", __func__, key, val);
        }
        buf += idx;
    }
    conn->http_error = 400;
    return -1;
}

// update connection settings with id values received from peer
int
update_settings(struct connection *conn, char *data, uint32_t len)
{
    size_t idx = 0;

    log_dbg(5, "%s: conn %p data %p len %i", __func__, conn, data, len);

    while (idx < len) {
        uint16_t id = 0;
        uint32_t val;

        memcpy(&id, (data + idx), sizeof(uint16_t));
        memcpy(&val, (data + idx + 2), sizeof(uint32_t));

        idx += 6;
        id = ntohs(id);
        val = ntohl(val);

        // update settings based on id value
        switch (id) {
        case 1:
            conn->h2_set.header_table_size = val;
            hpack_table_setsize(MIN(val, 65535), conn->hpack_dec);
            break;
        case 2:
            if (val != 0 && val != 1) {
                conn->h2_error = PROTOCOL_ERROR;
                return -1;
            }
            conn->h2_set.enable_push = val;
            break;
        case 3:
            conn->h2_set.max_concurrent_streams = val;
            break;
        case 4:
            if (val > ((1U << 31) - 1)) {
                conn->h2_error = FLOW_CONTROL_ERROR;
                return -1;
            }
            conn->h2_set.window_size = val;
            break;
        case 5:
            if (val < (1 << 14) || val > ((1 << 24) - 1)) {
                conn->h2_error = PROTOCOL_ERROR;
                return -1;
            }
            conn->h2_set.max_frame_size = val;
            break;
        case 6:
            conn->h2_set.max_header_list_size = val;
            break;
        default:
            break;
        }
    }
    // success
    return 0;
}

int
check_ss(struct stream *strm, enum h2_stream_state h2_ss, uint8_t f_typ)
{
    log_dbg(5, "%s: strm %p h2_ss %i f_typ %i", __func__, strm, h2_ss, f_typ);

    switch (h2_ss) {
    case SS_IDLE:
        if ((f_typ == HEADERS) || (f_typ == PRIORITY))
            return 0;

        break;
    case SS_RESERVED_LOCAL:
        if ((f_typ == RST_STREAM) || (f_typ == PRIORITY) || (f_typ == WINDOW_UPDATE))
            return 0;

        break;
    case SS_RESERVED_REMOTE:
        if ((f_typ == HEADERS) || (f_typ == RST_STREAM) || (f_typ == PRIORITY))
            return 0;

        break;
    case SS_HCLOSED_REMOTE:
        if ((f_typ == WINDOW_UPDATE) || (f_typ == PRIORITY) || (f_typ == RST_STREAM))
            return 0;

        if (strm)
            strm->h2_error = STREAM_CLOSED;

        return 1;
    case SS_CLOSED:
        if ((f_typ == WINDOW_UPDATE) || (f_typ == RST_STREAM) || (f_typ == PRIORITY))
            return 0;

        break;
    case SS_HCLOSED_LOCAL:
    case SS_OPEN:
    default:
        return 0;
    }

    log_dbg(5, "%s: unknown stream change", __func__);
    return -1;
}

int
process_frame(struct connection *conn, struct h2_frame frm, char *data)
{
    struct stream *strm = NULL;
    enum h2_stream_state h2_ss;
    int rv;

    log_dbg(5, "%s: conn %p frm %p data %p", __func__, conn, frm, data);
    log_dbg(5, "%s: (H2 frame) \nf_sid %i \nf_typ %i \nf_flg %i \nf_len %i", __func__, frm.f_sid, frm.f_typ, frm.f_flg, frm.f_len);

    if ((strm = h2_find_stream(conn, frm.f_sid)) == NULL)
        if (frm.f_sid > conn->h_sid)
            h2_ss = SS_IDLE;
        else
            h2_ss = SS_CLOSED;
    else
        h2_ss = strm->h2_ss;

    if (frm.f_sid != 0) {
        rv = check_ss(strm, h2_ss, frm.f_typ);

        if (rv < 0) {
            //conn->h2_error = PROTOCOL_ERROR;
            return -1;
        }
    }

    if (frm.f_typ == SETTINGS) {
        // if settings dont come on stream id 0, it's a protocol error
        if (strm && (strm->h2_sid != 0)) {
            conn->h2_error = PROTOCOL_ERROR;
            return -1;

        // if length is not a multiple of 6, it's a size error
        } else if (frm.f_len % 6 != 0) {
            conn->h2_error = FRAME_SIZE_ERROR;
            return -1;

        // if it's the end of a stream with settings, length must be 0 and we must send back settings confirmation
        } else if ((frm.f_flg & 1) != 0) {
            if (frm.f_len != 0) {
                conn->h2_error = FRAME_SIZE_ERROR;
                return -1;
            }
        // let's process the settings frame
        } else {
            // process settings
            if (update_settings(conn, data, frm.f_len) < 0)
                return -1;

            // flag to send settings
            conn->send_settings = 1;
        }
        return 1;
    } else if (frm.f_typ == WINDOW_UPDATE) {
        uint32_t inc;

        if (frm.f_len != 4) {
            conn->h2_error = FRAME_SIZE_ERROR;
            return -1;
        }

        //inc = ntohl(*(uint32_t *)data) & 0x7FFFFFFF;
        inc = (*(uint8_t *)&data[0] << 24) | (*(uint8_t *)&data[1] << 16) | (*(uint8_t *)&data[2] << 8) | (*(uint8_t *)&data[3]);

        if (frm.f_sid == 0) {
            if (inc == 0) {
                conn->h2_error = PROTOCOL_ERROR;
                return -1;
            } else if ((conn->h2_set.window_size + inc) > ((1U << 31) - 1)) {
                conn->h2_error = FLOW_CONTROL_ERROR;
                return -1;
            }
            conn->h2_set.window_size += inc;
        } else {
            if (h2_ss == SS_CLOSED) {
                //conn->h2_error = PROTOCOL_ERROR;
                //return -1;
                return 1;
            } else if (inc == 0) {
                strm->h2_error = PROTOCOL_ERROR;
                strm->h2_ss = SS_CLOSED;
            } else if ((strm->window_size + inc) > ((1U << 31) - 1))
                strm->h2_error = FLOW_CONTROL_ERROR;

            strm->window_size += inc;
        }
        return 1;

    // PRIORITY frame type receiver
    } else if (frm.f_typ == PRIORITY) {

        // stream id cannot be 0, protocol error as per rfc7540
        if (frm.f_sid == 0) {
            conn->h2_error = PROTOCOL_ERROR;
            return -1;
        }

        // priority frame length is 5 octets, check
        if (frm.f_len != 5) {
            conn->h2_error = FRAME_SIZE_ERROR;
            return -1;
        }

        // update latest seen stream id
        if ((conn->h_sid < frm.f_sid) && (frm.f_sid % 2 != 0))
        conn->h_sid = frm.f_sid;

        /* TODO: set priority data to stream */
        //set_priority(strm, frm.f_sid, (uint8_t *)data, IDLE);

        return 1;
    } else if (frm.f_typ == CONTINUATION) {
        if ((frm.f_flg & (FF_END_STREAM | FF_PADDED | FF_PRIORITY)) != 0) {
            conn->h2_error = PROTOCOL_ERROR;
            return -1;
        }
        return 1;
    } else if (frm.f_typ == HEADERS) {
        char *key = NULL;
        char *val = NULL;
        size_t dec_len = frm.f_len;
        enum http_method http_method;
        char *method = NULL;
        char *scheme = NULL;
        char *authority = NULL;
        int rv;

        if ((frm.f_sid == 0) || (frm.f_sid % 2 != 1)) {
            conn->h2_error = PROTOCOL_ERROR;
            return -1;
        } //else
        // TODO: Check number of open streams

        conn->cont_sid = (frm.f_flg & FF_END_HEADERS) == 0 ? frm.f_sid: 0;

        // if it's padded adjust the encoded block
        if (frm.f_flg & FF_PADDED) {
            dec_len -= (*(uint8_t *)data) + 1;
            data += 1;
        }

        // check if we need to reprioritize and adjust the encoded block
        if (frm.f_flg & FF_PRIORITY) {

            // check for proper priority length and throw error if bogus
            if (dec_len < 5) {
                conn->h2_error = PROTOCOL_ERROR;
                return -1;
            }
            /* TODO: set priority data to stream */
            // set_priority(strm, frm.f_sid, (uint8_t *)data, SS_OPEN);

            // adjust the decoding info
            dec_len -= 5;
            data += 5;
        }

        // update latest seen stream id
        if ((conn->h_sid < frm.f_sid) && (frm.f_sid % 2 != 0))
            conn->h_sid = frm.f_sid;

        if ((conn->hpack_hbd = hpack_decode((unsigned char *)data, dec_len, conn->hpack_dec)) != NULL) {
            struct hpack_header *hb;
            enum http_method http_method;
            char *auth = NULL;
            char *schm = NULL;

            TAILQ_FOREACH(hb, conn->hpack_hbd, hdr_entry) {

                if (strcasecmp(hb->hdr_name, ":method") == 0) {
                    method = hb->hdr_value;
                    if (strcasecmp(hb->hdr_value, "HEAD") == 0)
                        http_method = HEAD;
                    else if (strcasecmp(hb->hdr_value, "GET") == 0)
                        http_method = GET;
                    else if (strcasecmp(hb->hdr_value, "POST") == 0)
                        http_method = POST;
                    //else
                    //    log_dbg(5, "UNSUPPORTED_METHOD");
                } else if (strcasecmp(hb->hdr_name, ":authority") == 0) {
                    if (strm && strm->T) {
                        lua_pushstring(strm->T, hb->hdr_value);
                        lua_setfield(strm->T, -2, hb->hdr_name);
                    } else
                        auth = hb->hdr_value;
                } else if (strcasecmp(hb->hdr_name, ":scheme") == 0) {
                    if (strm && strm->T) {
                        lua_pushstring(strm->T, hb->hdr_value);
                        lua_setfield(strm->T, -2, hb->hdr_name);
                    } else
                        schm = hb->hdr_value;
                } else if (strcasecmp(hb->hdr_name, ":path") == 0) {
                    strm = start_lua(conn, &conn->thr->L_map, hb->hdr_value);

                    if ((strm == NULL) || (strm->T == NULL))
                        break;

                    // adding to strm
                    strm->h2_ss = SS_OPEN;

                    strm->h2_sid = frm.f_sid;
                    strm->h2_flg = frm.f_flg;

                    strm->method = method;
                    strm->http_method = http_method;
                    strm->scheme = schm;
                    strm->authority = auth;

                    // :path
                    lua_pushstring(strm->T, hb->hdr_value);
                    lua_setfield(strm->T, -2, hb->hdr_name);

                    // :method
                    lua_pushstring(strm->T, method);
                    lua_setfield(strm->T, -2, ":method");

                    // :authority
                    if (auth != NULL) {
                        lua_pushstring(strm->T, auth);
                        lua_setfield(strm->T, -2, ":authority");
                    }

                    // :scheme
                    if (schm != NULL) {
                        lua_pushstring(strm->T, schm);
                        lua_setfield(strm->T, -2, ":scheme");
                    }

                } else {
                    // remaining header fields
                    lua_pushstring(strm->T, hb->hdr_value);
                    lua_setfield(strm->T, -2, hb->hdr_name);
                }
            }
        } else {
            log_dbg(5, "%s: (hpack decoding failed)", __func__);
            return -1;
        }

        if (strm == NULL) {
            conn->h2_error = INTERNAL_ERROR;
            //conn->http_error = 500;
            return -1;
        } else if ((strm->lua_status = lua_run(strm->T, strm->L, 2)) > LUA_YIELD) {
            strm->http_status = INTERNAL_ERROR;
            return 1;
        }
    } else if (frm.f_typ == PING) {
        if (frm.f_len != 8) {
            conn->h2_error = FRAME_SIZE_ERROR;
            return -1;
        } else if (frm.f_sid != 0) {
            conn->h2_error = PROTOCOL_ERROR;
            return -1;
        } else if ((frm.f_flg & 1) == 0) {
            // send_ping;
            conn->send_ping = 1;
            conn->ping_data = (unsigned char *)(data + H2_HEADER_SIZE);
        }
    } else if (frm.f_typ == GOAWAY) {
        if (frm.f_len >= 8) {
            log_dbg(5, "Received GOAWAY (%d): %.*s", ntohl(*(uint32_t *)(data + H2_HEADER_SIZE + 4)), (frm.f_len - 8), ((data + H2_HEADER_SIZE + 8)));
        }
        return -1;
    } else if (frm.f_typ == RST_STREAM) {
        if (frm.f_len != 4) {
            conn->h2_error = FRAME_SIZE_ERROR;
            return -1;
        } else if (frm.f_sid == 0) {
            conn->h2_error = PROTOCOL_ERROR;
            return -1;
        } else if (strm == NULL || strm->h2_ss == SS_CLOSED) {
            if (frm.f_sid <= conn->h_sid) {
                conn->h2_error = PROTOCOL_ERROR;
                return -1;
            }
        } else if (strm->h2_ss == SS_IDLE) {
            conn->h2_error = PROTOCOL_ERROR;
            return -1;
        } else {
            log_dbg(5, "RST_STREAM: id %u, err %u", frm.f_sid, ntohl(*(uint32_t *)data));
            strm->h2_ss = SS_CLOSED;
        }
    } else if (frm.f_typ == DATA) {
        // return 0 because the rest of the processing needs to be done by the lua handler
        return 0;
    }
    // done processing the frame
    return 1;
}

int
http2_error(struct connection *conn, int code, uint32_t f_sid, char *buf, int len)
{
    uint8_t flags = 0;
    uint8_t f_typ;
    char date[32];
    int offset = 0;
    char *status;
    char sc[4];
    int w_len = 0;
    int s_len = 0;
    int f_len = 0;
    unsigned char *enc_b;
    size_t enc_l;

    log_dbg(5, "%s: conn %p code %i f_sid %i buf %p len %i", __func__, conn, code, f_sid, buf, len);

    if (code == 0)
        code = 500;

    snprintf(sc, sizeof(sc), "%i", code);

    memset(buf, 0, (sizeof (uint8_t) * (H2_HEADER_SIZE + 4)));
    conn->hpack_hbe = hpack_headerblock_new();

    f_typ = HEADERS;

    // add headers
    if (hpack_header_add(conn->hpack_hbe, ":status", sc, 0) == NULL)
        goto err;
    if (hpack_header_add(conn->hpack_hbe, "software", SOFTWARE_NAME, 0) == NULL)
        goto err;
    if (hpack_header_add(conn->hpack_hbe, "date", httpd_time(date, sizeof date), 0) == NULL)
        goto err;
    if (hpack_header_add(conn->hpack_hbe, "content-type", "text/html; charset=UTF-8", 0) == NULL)
        goto err;

    if ((enc_b = hpack_encode(conn->hpack_hbe, &enc_l, conn->hpack_enc)) == NULL) {
        conn->h2_error = COMPRESSION_ERROR;
        goto err;
    }

    memcpy(buf + (sizeof(uint8_t) * H2_HEADER_SIZE + offset), enc_b, enc_l);

    flags = FF_END_HEADERS;
    pack_frame_header((uint8_t *)buf, enc_l + offset, flags, f_typ, conn->h_sid);

    w_len += (H2_HEADER_SIZE + enc_l + offset);

    status = status_msg(code, &s_len);
    f_len = snprintf((buf + w_len + H2_HEADER_SIZE), MIN(conn->h2_set.max_frame_size, (len - w_len - H2_HEADER_SIZE)), HTTP_BODY_T, status, status);

    flags = FF_END_STREAM;
    pack_frame_header((uint8_t *)(buf + w_len), f_len, flags, DATA, conn->h_sid);
    w_len += (H2_HEADER_SIZE + f_len);

    hpack_headerblock_free(conn->hpack_hbe);
    return w_len;

err:
    // log if trying to write an error response fails and do nothing
    log_dbg(5, "%s: (error writing error response)", __func__);
    hpack_headerblock_free(conn->hpack_hbe);
    return 0;
}

int
http2_read(struct connection *conn, char *buf, int len)
{
    struct stream *strm;
    struct h2_frame frm;
    uint8_t pad = 0;
    int idx = 0;
    int rv;

    log_dbg(5, "%s: buf %p len %i", __func__, buf, len);

    // initial state, waiting HTTP/2 preface
    if (conn->h2_state == H2_WAITING_MAGIC) {
        if (len < CLIENT_MAGIC_LEN)
            goto again;

        // check if we have a valid HTTP/2 preface
        if (memcmp(CLIENT_MAGIC, buf, CLIENT_MAGIC_LEN) != 0) {
            conn->h2_error = PROTOCOL_ERROR;
            goto error;
        }

        // we got the preface, advance the index
        idx += CLIENT_MAGIC_LEN;
        conn->h2_state = H2_WAITING_SETTINGS;
    }

    // this loops over the buffer and decodes/processes frame by frame
    do {
        // parse frame header
        if (conn->f_len == 0) {

            // do we have a full header
            if ((idx + H2_HEADER_SIZE) > len)
                goto again;

            // decode frame header lengh settings
            frm.f_len = (*(uint8_t*)&buf[idx] << 16) | (*(uint8_t*)&buf[idx + 1] << 8) | (*(uint8_t*)&buf[idx + 2]);

            // do we have the full frame, now that we know its length
            if ((idx + H2_HEADER_SIZE + frm.f_len) > len)
                goto again;

            // decode remaining frame header settings
            frm.f_sid = (*(uint8_t*)&buf[idx + 5] << 24) | (*(uint8_t*)&buf[idx + 6] << 16) | (*(uint8_t*)&buf[idx + 7] << 8) | (*(uint8_t*)&buf[idx + 8]);
            frm.f_typ = *(uint8_t*)&buf[idx + 3];
            frm.f_flg = *(uint8_t*)&buf[idx + 4];

            // if the http/2 state is waiting for settings, make sure we got the settings frame without the ack
            if (conn->h2_state == H2_WAITING_SETTINGS) {
                if ((frm.f_typ != SETTINGS) || (frm.f_flg & 1)) {
                    conn->h2_error = PROTOCOL_ERROR;
                    goto error;
                // we got the settings frame we were waiting, change state to idle
                } else
                    conn->h2_state = H2_IDLE;
            }

            // if we found the stream, check to see if we're expecting a continuation
            if ((conn->cont_sid != 0) && ((conn->cont_sid != frm.f_sid) || (frm.f_typ != CONTINUATION))) {
                conn->h2_error = PROTOCOL_ERROR;
                goto error;
            }

            // we're going to receive more than we can handle, send error to client
            if (frm.f_len > h2_settings.max_frame_size) {
                conn->h2_error = FRAME_SIZE_ERROR;
                goto error;
            }

            // advance index, we got the header
            idx += H2_HEADER_SIZE;

            // attempt to find a stream and check if frame is allowed in current state
            rv = process_frame(conn, frm, buf + idx);

            // do we have an error while processing the frame
            if (rv < 0)
                goto error;

            // frame fully processed, check if we it's a control frame and need to reply or move on to the next one
            if (rv == 1) {
                idx += frm.f_len;

                if (conn->send_ping == 1)
                    break;

                continue;
            }

            // note how much data remains to be processed
            conn->f_len = frm.f_len;
        }

        // if we don't have a valid stream here, it's an error
        if (conn->strm == NULL) {
            conn->h2_error = INTERNAL_ERROR;
            goto error;
        }

        // read payload data from the conn buffer and pass it to lua
        rv = lev_read(conn->strm, &buf[idx], conn->f_len);

        // advance the index
        idx += rv;

        // if we have more to read, try again later
        if ((conn->f_len -= rv) > 0)
            return idx;

    // repeat and process another frame if we still have data in buffer
    } while (idx < len);

out:
    conn->cs |= IO_SEND;
    return idx;

again:
    conn->cs |= IO_RECV;
    return idx;

error:
    conn->cs |= IO_SEND;
    return len;
}


int
http_read(struct connection *conn, char *buf, int len)
{
    struct stream* strm = conn->strm;
    int idx = 0;
    int rv;

    log_dbg(5, "%s: buf %p len %i", __func__, buf, len);

    if (conn->strm == NULL) {
        // atempt to start http/2 via alpn
        if (conn->http_protocol == 0) {
            char const* alpn;

            alpn = br_ssl_engine_get_selected_protocol(&conn->ssl_sc.eng);
            if (alpn && (memcmp(proto_name, alpn, strlen(proto_name)) == 0)) {
                if (h2_init(conn) < 0) {
                    conn->http_error = 500;
                    goto err;
                }
                return (http2_read(conn, buf, len));
            }
            conn->http_protocol = HTTP11;
        }

        if ((idx = check_request(buf, len)) == 0) {
            if (len > BUFFER_SIZE) {
                conn->http_error = 400;
                goto err;
            }
            goto again;
        }

        rv = parse_http(conn, buf, idx);

        if (rv < 0)
            goto err;
    }

    idx += lev_read(conn->strm, (buf + idx), (len - idx));

    return idx;

again:
    conn->cs = IO_RECV;
    return 0;

err:
    conn->cs = IO_SEND;
    return 0;
}


int
http_header(struct stream *strm, char *buf, int len)
{
    lua_State *T = strm->T;
    char const* key;
    char const* val;
    int hlen = 0;
    int slen = 0;

    log_dbg(5, "%s: strm %p buf %p len %i", __func__, strm, buf, len);

    if (lua_type(T, 1) != LUA_TTABLE) {
        log_dbg(5, "httpd.header: function argument not a lua table");
        goto err;
    }

    lua_getfield(T, 1, "status");

    if (lua_isnil(T, 2)) {
        lua_pop(T, 1);
        lua_getfield(T, 1, ":status");

        if (lua_isnil(T, 2)) {
            lua_pop(T, 1);
            strm->conn->http_error = 500;
            goto err;
        }
    }

    val = luaL_checkstring(T, 2);
    lua_pop(T, 1);

    hlen = snprintf(buf, (len - hlen), "HTTP/1.1 %s\r\n", val);
    if (hlen >= len)
        goto err;

    lua_pushnil(T);
    while(lua_next(T, -2)) {
        key = lua_tostring(T, -2);
        val = lua_tostring(T, -1);
        if (strnstr(key, "status", 6) == NULL)
            hlen += snprintf(&buf[hlen], (len - hlen), "%s: %s\r\n", key, val);
        lua_pop(T, 1);
        if (hlen >= len)
            goto err;
    }

    if (strm->http_method != POST) {
        hlen += snprintf(&buf[hlen], (len - hlen), "\r\n");

        if (hlen >= len)
            goto err;
    }
    strm->ss = IO_SEND;
    strm->head = 0;

    lua_settop(T, 0);

    return hlen;

err:
    strm->ss = IO_ERROR;
    return 0;
}

void
conn_io(struct connection *conn)
{
    struct thread *thr = conn->thr;
    unsigned ssl_state;
    int sendrec = 0;
    int recvrec = 0;
    char *buf;
    size_t len;

    log_dbg(5, "%s: conn %p", __func__, conn);

    // this loop has two sections, setting up connection r/w events and getting app data in and out of the sll engine.
    // it tries to execute all states of the ssl engine before it needs to return and wait for any connection events.
    // once data is retrived or injected into the engine, it checks if any new events need to be added before it returns.
    // in addition to ssl states, is also checks for various app states and returns as required

    while (!(conn->cs & IO_ERROR)) {

        ssl_state = br_ssl_engine_current_state(&conn->ssl_sc.eng);

        log_dbg(5, "sendrec %i recvrec %i conn->cs %i", sendrec, recvrec, conn->cs);

        if (ssl_state == BR_SSL_CLOSED)
            break;

        if ((ssl_state & BR_SSL_SENDREC))
            if (sendrec++ == 0)
                EQ_ADD(thr->eq, &conn->ev, conn->fd, EV_WRITE, conn_write, conn, 0);

        if ((ssl_state & BR_SSL_RECVREC))
            if (recvrec++ == 0)
                EQ_ADD(thr->eq, &conn->ev, conn->fd, EV_READ, conn_read, conn, 0);

        if ((conn->cs == IO_CLOSE) && (sendrec == 0)) {
            br_ssl_engine_close(&conn->ssl_sc.eng);
            conntab_remove(conn);
            return;
        }

        // exit and wait for the events we set up previousy
        if ((sendrec > 1) || (recvrec > 1) || (conn->cs == 0))
            return;

        if ((ssl_state & BR_SSL_RECVAPP) && (conn->cs & IO_RECV)) {
            // remove the read flag and let the app side flag it again if needed
            conn->cs ^= IO_RECV;
            // update timer
            conntab_update(conn);
            // recv app data
            app_recv(conn);
        }

        if ((ssl_state & BR_SSL_SENDAPP) && (conn->cs & IO_SEND)) {
            // remove the write flag and let the app side flag it again if needed
            conn->cs ^= IO_SEND;
            // update timer
            conntab_update(conn);
            // send app data
            app_send(conn);
        }
    }

    if (conn->cs == IO_CLOSE)
        br_ssl_engine_close(&conn->ssl_sc.eng);
    // error condition, log and termintate connection
    else
        log_dbg(5, "%s: (SSL error: %d)", __func__, br_ssl_engine_last_error(&conn->ssl_sc.eng));

    conntab_remove(conn);
}


// main http2 write function
int
http2_write(struct connection *conn, char **buf, int len)
{
    struct stream *strm;
    struct stream *sp;
    int w_len = 0;
    int rv = 0;

    log_dbg(5, "%s: conn %p, buf %p len %i", __func__, conn, *buf, len);
    // TODO: server settings/flow control
    // we need to send the server h2_preface first (server settings) already assigned during h2_init
    if (conn->h2_preface == 1) {

        // check if the send buffer length is large enough for the header
        if ((w_len + H2_HEADER_SIZE + BUFFER_SIZE) > len)
            goto again;

        // create the server settings frame with our default values (NOT YET IMPLEMENTED)
        pack_frame_header((uint8_t *)(*buf), 0, 0, SETTINGS, 0);

        // flag we're done and advance length
        conn->h2_preface = 0;
        w_len += H2_HEADER_SIZE;
    }

    // we received the client settings frame, need to acknowledge it
    if (conn->send_settings == 1) {

        // check if the send buffer length is large enough for the header
        if ((w_len + H2_HEADER_SIZE + BUFFER_SIZE) > len)
            goto again;

        // create settings ack frame - 0 payload - and add it to the total length to send
        pack_frame_header((uint8_t *)(*buf + w_len), 0, 1, SETTINGS, 0);

        // flag we're done and advance length
        conn->send_settings = 0;
        w_len += H2_HEADER_SIZE;
    }

    if (conn->send_ping == 1) {

        // check if the send buffer length is large enough for the header
        if ((w_len + H2_HEADER_SIZE + BUFFER_SIZE) > len)
            goto again;

        // create settings ack frame - 0 payload - and add it to the total length to send
        pack_frame_header((uint8_t *)(*buf + w_len), 8, 1, PING, 0);
        memcpy((uint8_t *)(*buf + w_len + 9), conn->ping_data, 8);

        // flag we're done and advance length
        conn->send_ping = 0;
        w_len += (H2_HEADER_SIZE + 8);
    }

    if (conn->h2_error) {
        // check if the send buffer length is large enough for the header
        if ((w_len + H2_HEADER_SIZE + BUFFER_SIZE) > len)
            goto again;

        w_len += http2_error(conn, conn->http_error, conn->h_sid, *buf + w_len, len);
        // check if the send buffer length is large enough for the header
        if ((w_len + H2_HEADER_SIZE + BUFFER_SIZE) > len)
            goto again;

        pack_uint32((uint8_t *)(*buf + w_len + 9), conn->h_sid);
        pack_uint32((uint8_t *)(*buf + w_len + 13), conn->h2_error);

        pack_frame_header((uint8_t *)(*buf + w_len), 8, 0, GOAWAY, 0);

        w_len += (H2_HEADER_SIZE + 8);
        conn->h2_error = 0;
        goto err;
    }

    // loop through streams and process as needed
    TAILQ_FOREACH_SAFE(strm, &conn->strm_t, link, sp) {
        conn->strm = strm;
        uint8_t flags = 0;
        int f_len = 0;
        enum h2_frame_type f_typ = 0;
        uint32_t h2_sid;

        if ((strm->ss == IO_NONE) || (strm->ss == IO_RECV))
            continue;

        // check if our buffer is large enough to write a "full" header frame
        if ((w_len + H2_HEADER_SIZE + BUFFER_SIZE) > len)
            goto again;

        if (strm->h2_ss == SS_CLOSED) {
            strmtab_remove(strm);
            continue;
        }

        if (strm->head == 1) {
            rv = http2_header(strm, *buf + w_len, len);

            if (rv <= 0) {
                rv = http2_error(conn, strm->http_status, strm->h2_sid, *buf + w_len, len);
                strm->h2_error = INTERNAL_ERROR;
                strm->head = 0;
            }
            w_len += rv;
        }

        if (strm->h2_error == NO_ERROR)  {

            f_len = lev_write(strm, *buf + w_len + H2_HEADER_SIZE, MIN(conn->h2_set.max_frame_size, (len - w_len - H2_HEADER_SIZE)));
            h2_sid = strm->h2_sid;

            if (strm->lua_status != LUA_YIELD) {
                flags |= FF_END_STREAM;
                strm->h2_ss = SS_HCLOSED_LOCAL;
                strmtab_remove(strm);
            }

            if (!((f_len == 0) && (strm->lua_status == 1))) {
                pack_frame_header((uint8_t *)(*buf + w_len), f_len, flags, DATA, h2_sid);
                w_len += (H2_HEADER_SIZE + f_len);
            }
        }

        if (strm->h2_error != NO_ERROR) {
            if ((w_len + H2_HEADER_SIZE + BUFFER_SIZE) > len)
                goto again;

            pack_uint32((uint8_t *)(*buf + w_len + 9), strm->h2_error);
            pack_frame_header((uint8_t *)(*buf + w_len), 4, 0, RST_STREAM, strm->h2_sid);
            strmtab_remove(strm);

            w_len += (H2_HEADER_SIZE + 4);
        }
    }

out:
    conn->cs |= IO_RECV;
    return w_len;

again:
    conn->cs |= IO_SEND;
    return w_len;

err:
    conn->cs = IO_CLOSE;
    return w_len;
}

int
http_error(enum http_protocol http_proto, int code, char *buf, int len)
{
    const char *status;
    const char *body;

    char date[32];
    int wlen = 0;
    int slen = 0;

    log_dbg(5, "%s: http_protocol %i, code %i, buf %p, len %i", __func__, code, buf, len);

    status = status_msg(code, &slen);

    wlen = snprintf(buf, len, "%s %s\r\n", (http_proto) ? http_protocols[http_proto] : "HTTP/1.0", status);
    wlen += snprintf((buf + wlen), MAX(0, (len - wlen)), "Software: %s\r\n", SOFTWARE_NAME);
    wlen += snprintf((buf + wlen), MAX(0, (len - wlen)), "Date: %s\r\n", httpd_time(date, sizeof date));
    wlen += snprintf((buf + wlen), MAX(0, (len - wlen)), "Content-Type: %s\r\n", "text/html; charset=UTF-8");
    wlen += snprintf((buf + wlen), MAX(0, (len - wlen)), "Content-Length: %lu\r\n\r\n", strlen(HTTP_BODY_T) + 2 * (slen - 2));

    wlen += snprintf((buf + wlen), (len - wlen), HTTP_BODY_T, status, status);

    if (wlen >= len)
        log_dbg(5, "%s: write buffer too small, response trunkated", __func__);

    return wlen;
}


int
http_write(struct connection *conn, char *buf[], int len)
{
    struct stream *strm = conn->strm;
    char *rbuf;
    int rv = 0;

    log_dbg(5, "%s: conn %p, buf %p, len %i", __func__, conn, *buf, len);

    if (conn->http_error != 0) {
        rv = http_error(conn->http_protocol, conn->http_error, *buf, len);
        goto err;
    }

    if (strm->head == 1)
        rv = http_header(strm, *buf, len);

    if (strm->ss == IO_ERROR) {
        rv = http_error(conn->http_protocol, conn->http_error, *buf, len);
        strmtab_remove(strm);
        goto err;
    } else
        rv += lev_write(strm, *buf + rv, len - rv);

    if (strm->lua_status == LUA_YIELD)
    return rv;

    strmtab_remove(strm);

out:
    if (conn->conn_close != 1) {
        conn->cs = IO_RECV;
        return rv;
    }
err:
    conn->cs = IO_CLOSE;
    return rv;
}

int
alpn_h2_init(struct connection *conn)
{
    char const *alpn;
    int rv;

    log_dbg(5, "%s: conn %p", __func__, conn);

    alpn = br_ssl_engine_get_selected_protocol(&conn->ssl_sc.eng);
    if (alpn) {
        if (memcmp(proto_name, alpn, strlen(proto_name)) == 0)
            return (h2_init(conn));
        else
            log_dbg(5, "%s: (ALPN negotiation failure)", __func__);

        return (0);
    }
    log_dbg(5, "%s: (ALPN extension not found)", __func__);
    return (0);
}

void
app_recv(struct connection *conn)
{
    unsigned char *buf;
    size_t len;
    ssize_t rv;

    log_dbg(5, "%s: conn %p", __func__, conn);

    buf = br_ssl_engine_recvapp_buf(&conn->ssl_sc.eng, &len);

    memcpy(conn->rbuf + conn->rlen, buf, len);
    conn->rlen += len;

    if (conn->http_protocol == HTTP2)
        rv = http2_read(conn, conn->rbuf, conn->rlen);
    else
        rv = http_read(conn, conn->rbuf, conn->rlen);

    if (rv > 0) {
        len = len - (conn->rlen - rv);
        conn->rlen = 0;
    } else if (conn->cs == 0)
        return;

    br_ssl_engine_recvapp_ack(&conn->ssl_sc.eng, len);
}

void
app_send(struct connection *conn)
{
    char *buf;
    size_t len;
    ssize_t rv;

    log_dbg(5, "%s: conn %p", __func__, conn);

    buf = (char *) br_ssl_engine_sendapp_buf(&conn->ssl_sc.eng, &len);

    if (len < BUFFER_SIZE)
        return;

    if (conn->http_protocol == HTTP2)
        rv = http2_write(conn, &buf, len);
    else
        rv = http_write(conn, &buf, len);

    if (rv < 0) {
        conn->cs = IO_ERROR;
    } else if (rv > 0) {
        br_ssl_engine_sendapp_ack(&conn->ssl_sc.eng, rv);
        br_ssl_engine_flush(&conn->ssl_sc.eng, 0);
    }
}

void
conn_read(struct edata *ev)
{
    struct connection *conn = ev->ctx;
    unsigned char *buf;
    ssize_t rv;
    size_t len;

    log_dbg(5, "%s: ev %p", __func__, ev);

    buf = br_ssl_engine_recvrec_buf(&conn->ssl_sc.eng, &len);

    rv = recv(ev->fd, buf, len, 0);

    if (rv <= 0) {
        if (rv == -1 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
            return;
        log_dbg(5, "socket read error: %s", strerror(errno));
        conn->cs = IO_CLOSE;
    } else
        br_ssl_engine_recvrec_ack(&conn->ssl_sc.eng, rv);

    EQ_DEL(conn->thr->eq, &conn->ev, ev->fd, EV_READ);
    return (conn_io(conn));
}

void
conn_write(struct edata *ev)
{
    struct connection *conn = ev->ctx;
    unsigned char *buf;
    ssize_t rv;
    size_t len;

    log_dbg(5, "%s: ev %p", __func__, ev);

    buf = br_ssl_engine_sendrec_buf(&conn->ssl_sc.eng, &len);

    rv = write(ev->fd, buf, len);

    if (rv <= 0) {
        if (rv == -1 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
            return;
        log_dbg(5, "socket write error: %s", strerror(errno));
        conn->cs = IO_ERROR;
    } else {
        br_ssl_engine_sendrec_ack(&conn->ssl_sc.eng, rv);
        if (rv < len)
            return;
    }

    EQ_DEL(conn->thr->eq, &conn->ev, ev->fd, EV_WRITE);

    if (conn->cs != IO_CLOSE)
        return (conn_io(conn));

    br_ssl_engine_close(&conn->ssl_sc.eng);
    conntab_remove(conn);
}
