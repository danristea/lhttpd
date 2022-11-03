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

#define _GNU_SOURCE

#include <fcntl.h>
#include "lualib.h"
#include "lauxlib.h"

#include "httpd.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>


static void
lh_setenv(lua_State *L, const luaL_Reg *l, int nup)
{
    //lua_newtable(L);
    lua_getfield(L, LUA_REGISTRYINDEX, "httpd.data");

//    lua_createtable (L, 0, 1); /* its metatable, which is */
//    lua_pushliteral (L, "__mode"); /* used to make environment */
//    lua_pushliteral (L, "k"); /* weak in the keys */
//    lua_rawset (L, -3); /* metatable.__mode = "k" */
//    lua_setmetatable (L, -2);

    luaL_checkstack(L, nup + 1, "too many upvalues");
    for (; l->name != NULL; l++) {  /* fill the table with given functions */
        int i;
        lua_pushstring(L, l->name);
        for (i = 0; i < nup; i++)  /* copy upvalues to the top */
            lua_pushvalue(L, - (nup + 1));
        lua_pushcclosure(L, l->func, nup);  /* closure with those upvalues */
        lua_settable(L, - (nup + 3));
    }
    lua_pop(L, nup);  /* remove upvalues */
}

struct stream *
lh_getstrm(lua_State *L)
{
    struct stream *strm;

    lua_pushthread(L);
    lua_rawget(L, LUA_REGISTRYINDEX);

    strm = (struct stream *) lua_touserdata(L, -1);
    lua_pop(L, 1);

    return strm;
}

static void
lh_setupval(lua_State *L)
{
    lua_pushvalue(L, lua_upvalueindex(1));
    lua_insert(L, -3);
    lua_rawset(L, -3);
    lua_pop(L, 1);
}

void*
lh_getupval(lua_State *L)
{
    void* val;

    lua_pushvalue(L, lua_upvalueindex(1));
    lua_insert(L, -2);
    lua_rawget(L, -2);
    val = (void*) lua_touserdata(L, -1);
    lua_pop(L, 2);

    return val;
}

int
lua_run(lua_State *T, lua_State *L, int n)
{
#if LUA_VERSION_NUM >= 504
    int na;
    lua_resume(T, L, n, &na);
#else
    lua_resume(T, n);
#endif
}

struct lua_handler *
find_handler(struct lua_state_map* Lm, char* name, char* query)
{
    struct lua_handler* lh;
    int len;

    if (query)
        len = query - name - 1;
    else
        len = strlen(name);

    // loop thourh handlers
    SIMPLEQ_FOREACH(lh, &Lm->l_hand, next) {
        if (strncmp(lh->name, name, len) || (len != strlen(lh->name)))
            continue;

        return lh;
    }

    return NULL;
}

void
strm_resume(struct stream *strm)
{
    struct connection *conn = strm->conn;

    log_dbg(5, "%s: strm %p", __func__, strm);

    // reset the stream state
    strm->ss = IO_NONE;

    // resume lua execution with the complete event data on the lua stack
    if ((strm->lua_status = lua_run(strm->T, strm->L, lua_gettop(strm->T))) == 0)
        strm->ss = IO_SEND;

    // check for new lua blocking before resuming connection
    if (strm->ss != IO_NONE) {
        conn->cs |= strm->ss;
        return conn_io(conn);
    }
}


// read data from recv buffer into lua
// returns how much was read by lua
int
lev_read(struct stream *strm, char *buf, int len)
{
    struct connection *conn = strm->conn;
    lua_State *T = strm->T;
    int idx = 0;

    log_dbg(5, "%s: strm %p buf %p len %i", __func__, strm, buf, len);

    // repeat until lua reads all data from recv buffer
    while (idx < len) {

        // check for blocking and return current idx as strm->io_len may have a new value
        if (strm->ss != IO_RECV)
            break;

        // check if we have engough data in buffer
        if ((len - idx) < strm->io_len)
            break;

        // pass it to lua
        lua_pushlstring(T, &buf[idx], strm->io_len);

        // update index before strm->io_len may have a new value
        idx += strm->io_len;

        // resume lua execution with the value we passed
        if ((strm->lua_status = lua_run(T, strm->L, 1)) != LUA_YIELD) {
            //strm->ss = IO_CLOSE;
            break;
        }
    }

    // flag the connection about app i/o activity
    strm->conn->cs |= strm->ss;

    // return index of how much we sent to lua
    return idx;
}

// write lua data into the send buffer
// returns how much was written to send buffer
int
lev_write(struct stream *strm, char *buf, int len)
{
    struct connection *conn = strm->conn;
    lua_State *T = strm->T;
    int w_len;
    int idx = 0;

    log_dbg(5, "%s: strm %p buf %p len %i", __func__, strm, buf, len);

    // repeat until send buffer has space left
    while (idx < len) {

        if ((strm->ss != IO_SEND) || (strm->head != 0) || (strm->lua_status != 1))
            break;

        w_len = MIN((len - idx), (strm->io_len - strm->io_idx));

        memcpy(buf + idx, strm->io_buf + strm->io_idx, w_len);

        idx += w_len;

        if ((strm->io_idx += w_len) < strm->io_len)
            break;

        // resume lua execution after we retrieved the value
        if ((strm->lua_status = lua_run(strm->T, strm->L, 0)) != LUA_YIELD) {
//            strm->ss = IO_CLOSE;
            break;
        }
    }

    // flag the connection about app i/o activity
    strm->conn->cs |= strm->ss;

    // return index of how much we received from lua
    return idx;
}

// read event callback function for lua fd
// resumes the connection transmission when lua stops blocking
void
strm_read(struct edata *ev)
{
    struct aio_data *aio_d = ev->ctx;
    struct stream *strm = aio_d->ctx;
    struct connection *conn = strm->conn;
    lua_State *T = strm->T;
    ssize_t len;

    log_dbg(5, "%s: ev %p", __func__, ev);

    // read event fired, let's do some reading
    len = read(ev->fd, aio_d->buf + aio_d->pos, MIN(BUFFER_SIZE, (aio_d->len - aio_d->pos)));

    if (len < 0) {
        log_dbg(5, "errno: %s", strerror(errno));
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
            return;

        // handle some fd error
    } else if (len == 0) {
        if (aio_d->pos > 0) {
            lua_pushlstring(T, aio_d->buf, aio_d->pos);
        } else
            lua_pushnil(strm->T);

    } else {
        if ((aio_d->pos += len) < aio_d->len)
            return;

        //luaL_pushresult(&strm->lb);
        lua_pushlstring(T, aio_d->buf, aio_d->len);
    }

    // remove event from firing - we read all the data
    EQ_DEL(conn->thr->eq, ev, ev->fd, EV_READ);

    return strm_resume(strm);
}

// write event callback function for lua fd
// resumes the connection transmission when lua stops blocking
void
strm_write(struct edata *ev)
{
    struct aio_data *aio_d = ev->ctx;
    struct stream *strm = aio_d->ctx;
    struct connection *conn = strm->conn;
    lua_State *T = strm->T;
    ssize_t len;

    log_dbg(5, "%s: ev %p", __func__, ev);

    // write event fired, let's do some writing
    len = write(ev->fd, aio_d->buf + aio_d->pos, (aio_d->len - aio_d->pos));

    // writing returned an error, log it and check if it's recovarable
    if (len < 0) {
        log_dbg(5, "errno: %s", strerror(errno));
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
            return;
        }
        // handle some fs error
    // we wrote some data, check if we're done writing and add it to the lua buffer
    } else {
        if ((aio_d->pos += len) < aio_d->len)
            return;
    }

    lua_pushnumber(T, aio_d->pos);

    // remove event from firing - we wrote all the data
    EQ_DEL(conn->thr->eq, ev, ev->fd, EV_WRITE);

    return strm_resume(strm);
}

void stack_dump(lua_State *L, const char *stackname) {
  int i;
  int top = lua_gettop(L);
  printf("--------------- %s STACK ---------------\n", stackname);
  for (i = top; i >= 1; i--) {
    int t = lua_type(L, i);
    printf("[%2d - %8s] : ", i, lua_typename(L, t));
    switch (t) {
      case LUA_TSTRING:
        printf("%s", lua_tostring(L, i));
        break;
      case LUA_TBOOLEAN:
        printf(lua_toboolean(L, i) ? "true" : "false");
        break;
      case LUA_TNUMBER:
        printf("%g", lua_tonumber(L, i));
        break;
      case LUA_TNIL:
        printf("nil");
        break;
      case LUA_TNONE:
        printf("none");
        break;
      case LUA_TFUNCTION:
        printf("<function %p>", lua_topointer(L, i));
        break;
      case LUA_TTABLE:
        printf("<table %p>", lua_topointer(L, i));
        break;
      case LUA_TTHREAD:
        printf("<thread %p>", lua_topointer(L, i));
        break;
      case LUA_TUSERDATA:
        printf("<userdata %p>", lua_topointer(L, i));
        break;
      case LUA_TLIGHTUSERDATA:
        printf("<lightuserdata %p>", lua_topointer(L, i));
        break;
      default:
        printf("unknown %s", lua_typename(L, t));
        break;
    }
    printf("\n");
  }
  printf("--------------- %s STACK ---------------\n", stackname);
}

static int
lua_read(lua_State *L)
{
    struct stream *strm;
    int len;

    log_dbg(5, "%s: L %p", __func__, L);

    // check that the function is called with the right number of arguments
    if (lua_gettop(L) != 2) {
        log_ex(NULL, 1, "httpd.read: expects exactly 2 arguments");
        return 0;
    }

    // check that buffer size is a number
    if ((len = lua_tointeger(L, 2)) < 1) {
        log_ex(NULL, 1, "httpd.read: buffer size not a number");
        return 0;
    }

    // grab the strm stucture corresponding with the lua context
    strm = lh_getstrm(L);

    // if first argument is nil, we're reading data from the connection
    if (lua_isnil(L, 1)) {
        if (strm->http_method == GET) {
            log_dbg(5, "lua_read: cannot read from connection during GET method");
            lua_settop(L, 0);
            lua_pushnil(L);
            return 1;
        }

        // reset counters
        strm->io_len = len;
        strm->io_idx = 0;

        strm->ss = IO_RECV;
    // argument is a lua FILE structure, get it's file descriptor and add it to the event queue
    } else {
        struct aio_data *aio_d;
        FILE *f;
        long int pos;
        int fd;

        // grab the FILE structure from lua
        f = *(FILE **) luaL_checkudata(L, 1, LUA_FILEHANDLE);

        lua_pushvalue(L, 1);
        aio_d = (struct aio_data *) lh_getupval(L);

        if ((aio_d == NULL) || (aio_d->fd < 0)) {
            struct stat st;

            lua_pushvalue(L, 1);
            aio_d = (struct aio_data *) lua_newuserdata(L, sizeof(struct aio_data));
            // check is malloc succeeded
            if (aio_d == NULL)
                return luaL_error(L, "malloc error");

            memset(aio_d, 0, sizeof(struct aio_data));
            lh_setupval(L);

            aio_d->buf = (char *) lua_newuserdata(L, sizeof(char) * (len + 1));
            lua_pushthread(L);
            lua_insert(L, -2);
            lh_setupval(L);

            // retreive the corresponding file descriptor from the FILE structure
            if ((aio_d->fd = fileno(f)) < 0)
                return luaL_error(L, "invalid file descriptor associated with lua stream");

            aio_d->ctx = strm;

            // get value of position indicator for the lua FILE
            pos = ftell(f);

            // if the returned position is valid, calculate file size so we can stet up AIO reads
            if ((aio_d->pos = ftell(f)) >= 0) {
                fstat(aio_d->fd, &st);
                aio_d->flen = st.st_size;
                //fcntl(aio_d->fd, F_SETFL, fcntl(aio_d->fd, F_GETFL, 0) | O_DIRECT);
            } else {
                // it's a FIFO stream, set it to non-blocking before adding it to the event system
                fcntl(aio_d->fd, F_SETFL, fcntl(aio_d->fd, F_GETFL, 0) | O_NONBLOCK);
                aio_d->flen = -1;
            }

        } else if (len > aio_d->len) {
            aio_d->buf = (char *) lua_newuserdata(L, sizeof(char) * (len + 1));
            lua_pushthread(L);
            lua_insert(L, -2);
            lh_setupval(L);
        }

        if (aio_d->flen > -1) {
            if ((aio_d->len = MIN((aio_d->flen - aio_d->pos), len)) <= 0)
                return 0;

            schedule_aio(strm->conn->thr->aio, aio_d, EV_READ);
        } else {
            aio_d->pos = 0;
            aio_d->len = len;
            EQ_ADD(strm->conn->thr->eq, &strm->ev, aio_d->fd, EV_READ, strm_read, aio_d, 0);
        }

        // flag that we need to wait for ready event
        strm->ss = IO_NONE;
    }

    lua_settop(L, 0);
    // yield lua coroutine
    return lua_yield(L, 0);
}


static int
lua_write(lua_State *L)
{
    struct stream *strm;
    struct connect *conn;
    const char *buf;
    size_t len;

    log_dbg(5, "%s: L %p", __func__, L);

    // check that the function is called with the right number of arguments
    if (lua_gettop(L) != 2) {
        log_ex(NULL, 1, "httpd.write expects exactly 2 arguments");
        return 0;
    }

    // check that buffer size is a number
    if (lua_type(L, 2) != LUA_TSTRING) {
        log_dbg(5, "%s: (value not a string)", __func__);
        return 0;
    }

    // grab the strm stucture corresponding with the lua context
    strm = lh_getstrm(L);

    // if first argument is nil, we're writing data into the connection
    if (lua_isnil(L, 1)) {
        if (strm->http_method == POST) {
            log_dbg(5, "lua_write: cannot write into connection during POST method");
            return 0;
        }

        // reset counters
        strm->io_idx = 0;
        strm->io_buf = (char *) lua_tolstring(L, 2, &strm->io_len);

        // flag that stream has data to send
        strm->ss = IO_SEND;

    // argument is a lua FILE structure, get it's file descriptor and add it to the event queue
    } else {
        struct aio_data *aio_d;
        FILE *f;
        int fd;
        long int pos;

        // grab the file structure from lua
        f = *(FILE **) luaL_checkudata(L, 1, LUA_FILEHANDLE);

        lua_pushvalue(L, 1);
        aio_d = (struct aio_data *) lh_getupval(L);

        // it's a new file stream, init and get stats
        if ((aio_d == NULL) || (aio_d->fd < 0)) {
            struct stat st;

            lua_pushvalue(L, 1);
            aio_d = (struct aio_data *) lua_newuserdata(L, sizeof(struct aio_data));
            memset(aio_d, 0, sizeof(struct aio_data));

            lh_setupval(L);

            // check is malloc succeeded
            if (aio_d == NULL)
                return luaL_error(L, "malloc error");

            // retreive the corresponding file descriptor from the FILE structure
            if ((aio_d->fd = fileno(f)) < 0)
                return luaL_error(L, "invalid file descriptor associated with lua stream");

            aio_d->ctx = strm;

            // get value of position indicator for the lua FILE
            aio_d->pos = ftell(f);

            // if the returned position is valid, calculate file size so we can stet up AIO reads
            if (aio_d->pos >= 0) {
                //fcntl(aio_d->fd, F_SETFL, fcntl(aio_d->fd, F_GETFL, 0) | O_DIRECT); // why does this break it, bug?
            } else
                aio_d->flen = -1;
                // it's a FIFO stream, set it to non-blocking before adding it to the event system
                fcntl(aio_d->fd, F_SETFL, fcntl(aio_d->fd, F_GETFL, 0) | O_NONBLOCK);
        }

        aio_d->buf = (char *) lua_tolstring(L, 2, &aio_d->len);

        if (aio_d->flen > -1) {
            if (aio_d->len <= 0)
                return 0;

            schedule_aio(strm->conn->thr->aio, aio_d, EV_WRITE);
        } else {
            aio_d->pos = 0;
            // add it to the event queue to fire when write ready
            EQ_ADD(strm->conn->thr->eq, &strm->ev, aio_d->fd, EV_WRITE, strm_write, aio_d, 0);
        }

        // flag that we need to wait for ready event
        strm->ss = IO_NONE;
    }

    lua_settop(L, 0);
    // yield lua coroutine
    return lua_yield(L, 0);
}

static int
lua_header(lua_State *L)
{
    struct stream *strm;

    log_dbg(5, "%s: L %p", __func__, L);

    // check that the function is called with the right number of arguments
    if (lua_gettop(L) != 1) {
        log_ex(NULL, 1, "httpd.header: expects exactly 1 argument");
        return 0;
    }

    strm = lh_getstrm(L);

    strm->io_len = 0;
    strm->io_idx = 0;

    strm->ss = IO_SEND;
    strm->head = 1;

    return lua_yield(L, 1);
}

static int
luaopen_httpd(lua_State *L)
{
    log_dbg(5, "%s: L %p", __func__, L);

    lua_newtable (L); /* make environment "private storage" */
//    lua_createtable (L, 0, 1); /* its metatable, which is */
//    lua_pushliteral (L, "__mode"); /* used to make environment */
//    lua_pushliteral (L, "k"); /* weak in the keys */
//    lua_rawset (L, -3); /* metatable.__mode = "k" */
//    lua_setmetatable (L, -2);

    struct luaL_Reg functions[] = {
        { "read",    lua_read },
        { "register_handler",  register_handler },
        { "write",    lua_write },
        { "header",  lua_header},
        { NULL, NULL }
    };

    lh_setenv(L, functions, 1);

    lua_pushstring(L, "httpd 1.0.0");
    lua_setfield(L, -2, "_VERSION");
    return 1;
}

int
lua_map_create(struct thread *thr, struct l_map *l_map)
{
    struct lua_map *lm;

    log_dbg(5, "%s: thr %p l_map %p", __func__, thr, l_map);

    SIMPLEQ_FOREACH(lm, l_map, next) {
        struct lua_state_map *Lm;

        if ((access(lm->script, F_OK) < 0))
            return -1;

        if ((Lm = malloc(sizeof(struct lua_state_map))) == NULL)
            return -1;

        while ((*lm->prefix == '/') && (*(lm->prefix + 1) == '/'))
                lm->prefix++;

        Lm->prefix = lm->prefix;
        Lm->script = lm->script;
        SIMPLEQ_INIT(&Lm->l_hand);

        if ((Lm->L = luaL_newstate()) == NULL)
            return -1;

        luaL_openlibs(Lm->L);
        lua_getglobal(Lm->L, "package");
        lua_getfield(Lm->L, -1, "preload");
        lua_pushcfunction(Lm->L, luaopen_httpd);
        lua_setfield(Lm->L, -2, "httpd");
        lua_pop(Lm->L, 2);

        lua_pushstring(Lm->L, "lua_state_map");
        lua_pushlightuserdata(Lm->L, Lm);
        lua_settable(Lm->L, LUA_REGISTRYINDEX);

        lua_newtable(Lm->L);
        lua_newtable(Lm->L);
        lua_pushstring(Lm->L, "k");
        lua_setfield(Lm->L, -2, "__mode");
        lua_setmetatable(Lm->L, -2);
        lua_setfield(Lm->L, LUA_REGISTRYINDEX, "httpd.data");

//        luaL_getmetatable(Lm->L, LUA_FILEHANDLE);
//        lua_pushcclosure(L, cleanup_fn, 1);
//        lua_pushcfunction(Lm->L, cleanup_fn);
//        lua_setfield(Lm->L, -2, "__gc");
//        lua_setmetatable(Lm->L, -2);

        if (luaL_loadfile(Lm->L, lm->script)) {
            log_dbg(5, "failed to load script %s: %s", lm->script, lua_tostring(Lm->L, -1));
            return -1;
        }

        if (lua_pcall(Lm->L, 0, 0, 0)) {
            log_dbg(5, "failed to execute script %s: %s", lm->script, lua_tostring(Lm->L, -1));
            return -1;
        }

        SIMPLEQ_INSERT_TAIL(&thr->L_map, Lm, next);
    }

    return 0;
}


static int
register_handler(lua_State *L)
{
    struct lua_state_map *Lm;
    struct lua_handler *lh;
    struct thread *thr;

    log_dbg(5, "%s: L %p", __func__, L);

    if ((lh = malloc(sizeof(struct lua_handler))) == NULL)
        return -1;

    lua_pushstring(L, "lua_state_map");
    lua_gettable(L, LUA_REGISTRYINDEX);
    Lm = lua_touserdata(L, -1);

    lua_pop(L, 1);

    luaL_checkstring(L, 1);
    luaL_checktype(L, 2, LUA_TFUNCTION);

    lh->name = e_strdup(lua_tostring(L, 1));
    lh->ref = luaL_ref(L, LUA_REGISTRYINDEX);

    SIMPLEQ_INSERT_TAIL(&Lm->l_hand, lh, next);

    return 0;
}

void
lh_aio_dispatch(struct aio_data *aio_d)
{
    struct stream *strm;
    int rv;

    log_dbg(5, "%s: aio_d %p", __func__, aio_d);

    if (aio_d == NULL)
        return;

    if ((strm = (struct stream *) aio_d->ctx) == NULL)
        return;

    rv = aio_d->len;

    if (rv < 0) {
        log_dbg(5, "%s: (AIO Error)", __func__);
        strm->h2_error = INTERNAL_ERROR;
        lua_pushnil(strm->T);
    } else if (aio_d->buf != NULL) {
        if (rv == 0)
            lua_pushnil(strm->T);
        else
            lua_pushlstring(strm->T, aio_d->buf, rv);
    }

    return (strm_resume(strm));
}
