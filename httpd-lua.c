#define _GNU_SOURCE

#include <fcntl.h>
#include "lualib.h"
#include "lauxlib.h"

#include "httpd.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

int
lua_run(lua_State *T, lua_State *L, int n)
{
#if LUA_VERSION_NUM >= 504
{
	  int na;
	  lua_resume(T, L, n, &na);
}
#else
    lua_resume(T, n);
#endif
} //f


long
fsize(FILE *F)
{
    long pos, end;

		pos = ftell(F);
		if (pos < 0)
		    return -1;

    fseek(F, 0, SEEK_END);
    end = ftell(F);
    fseek(F, pos, SEEK_SET); //vrestore original position

    return end;
} //f

struct lua_handler*
find_handler(struct lua_state_map* Lm, char* name)
{
		struct lua_handler* lh;

	  // loop thourh handlers
	  SIMPLEQ_FOREACH(lh, &Lm->l_hand, next) {
			  if (strcmp(lh->name, name))
				    continue;

				return lh;
		}

		return NULL;
} //f

void
strm_resume(struct stream *strm)
{
	  strm->ss ^= SS_WAIT;

	  // reset event counters
	  strm->io_idx = 0;
	  strm->io_len = 0;

	  // resume lua execution with the complete event data on the lua stack
	  if ((strm->lua_status = lua_run(strm->T, strm->L, 1)) == 0)
			  lthread_remove(strm->L, &strm->T);

	  // check for new lua blocking before resuming connection
	  if (!(strm->ss & SS_WAIT))
			  return conn_resume(strm);
} //f watch for lua_run int arg 1

void
lthread_remove(lua_State *L, lua_State **T)
{
		struct stream* strm;
	  int i;

		lua_pushlightuserdata(*T, *T);
		lua_gettable(*T, LUA_REGISTRYINDEX);
		strm = (struct stream*) lua_touserdata(*T, -1);

		//lua_gc(*T, LUA_GCCOLLECT, 0);
		//lua_gc(L, LUA_GCCOLLECT, 0);
    //lua_gc(L, LUA_GCSTOP, 0);
		//lua_setgcthreshold(L,0)

		//reset_headers(strm);
		//new_strm(strm->conn);
		//reset_headers(strm);

	  int top = lua_gettop(L);
	  for (i = 1; i <= top; i++) {
			  // find the lua thread to remove from the main lua state
			  if (lua_tothread(L, i) == *T) {
					  // remove everything from the thread stack so the gc can do its job
						lua_settop(*T, 0);
						//lua_close (*T);
					  //stack_dump(*T, "FOR THE GC");
					  stack_dump(L, "BEFORE thread POP");
						log_dbg(5, "DELETING THREAD REFERENCE FOR GC TO DO ITS JOB");
						//lua_gc(L, LUA_GCCOLLECT, 0); // keep this!!
						lua_remove(L, i);
						//fclose(*strm->f);

						//lua_gc(L, LUA_GCCOLLECT, 0);
						*T = NULL;

						stack_dump(L, "AFTER thread POP");
						//log_dbg(5, "HERE?");
						return;
				}
		}
}

// read data from recv buffer into lua
// returns how much was read by lua
int
lev_read(struct stream* strm, char* buf, int len)
{
	  struct connect* conn = strm->conn;
	  lua_State* T = strm->T;
		int idx = 0;

		// repeat until lua reads all data from recv buffer
		while (idx < len) {

				// check for blocking and return current idx as strm->io_len may have a new value
				//if (strm->status == SS_WAIT)
				//log_dbg(5, "gotta exit ss %i ", strm->ss);
				//if (strm->fsio == 1)
				if ((strm->ss != SS_RECV) || (strm->ss & SS_WAIT))
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
						lthread_remove(strm->L, &strm->T);
					  break;
				}
		}

		// return index of how much we sent to lua
		return idx;
}

// write lua data into the send buffer
// returns how much was written to send buffer
int
lev_write(struct stream* strm, char* buf, int len)
{
	  struct connect* conn = strm->conn;
	  lua_State* T = strm->T;
		int w_len;
		int idx = 0;

		// repeat until send buffer has space left
		while (idx < len) {
						//log_dbg(5, "strm is: %p", strm);
			  // check for blocking and return current idx as strm->io_len may have a new value
				//if (strm->status == SS_WAIT)
				//if (strm->fsio == 1)
				if ((strm->ss != SS_SEND) || (strm->ss & SS_WAIT))
						break;

				w_len = MIN((len - idx), (strm->io_len - strm->io_idx));

				memcpy(buf + idx, strm->io_buf + strm->io_idx, w_len);

				idx += w_len;

				if ((strm->io_idx += w_len) < strm->io_len)
						break;

				// resume lua execution after we retrieved the value
		    if ((strm->lua_status = lua_run(strm->T, strm->L, 0)) != LUA_YIELD) {
				    lthread_remove(strm->L, &strm->T);
						break;
				}
		}

		// return index of how much we received from lua
		return idx;
}

// read event callback function for lua fd
// resumes the connection transmission when lua stops blocking
void
//strm_read(int fd, void* ctx)
strm_read(struct edata *ev)
{
		struct stream* strm = ev->ctx;
	  struct connect* conn = strm->conn;
	  lua_State* T = strm->T;
		char buf[BUFFER_SIZE];
	  ssize_t len;

		// read event fired, let's do some reading
		len = read(ev->fd, &buf, MIN(BUFFER_SIZE, (strm->io_len - strm->io_idx)));

		if (len < 0) {
			  log_dbg(5, "errno: %s", strerror(errno));
			  if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
					  return;
			  // handle some fd error
		} else if (len == 0) {
				if (strm->io_idx > 0) {
					  strm->io_len = strm->io_idx; // assign 0 to the len so we can pushnil next time
					  luaL_pushresult(&strm->lb);
				} else
            lua_pushnil(strm->T);
		} else {
				luaL_addlstring(&strm->lb, buf, len);
				if ((strm->io_idx += len) < strm->io_len)
			      return;

				luaL_pushresult(&strm->lb);
		}

		//memset(&strm->aio_d, 0, sizeof (struct aio_data));

		// remove event from firing - we read all the data
	  EQ_DEL(conn->thr->eq, &strm->ev, ev->fd, EV_READ);

		// signal we're no longer blocked by lua
		strm->ss ^= SS_WAIT;

    // reset event counters
		strm->io_len = 0;
		strm->io_idx = 0;

	  // resume lua execution with the complete string on the lua stack
    if ((strm->lua_status = lua_run(T, strm->L, 1)) == 0)
	      lthread_remove(strm->L, &strm->T);

		// check for new lua blocking before resuming connection
		if (!(strm->ss & SS_WAIT))
		    return conn_resume(strm);
}

// write event callback function for lua fd
// resumes the connection transmission when lua stops blocking
void
strm_write(struct edata *ev)
{
		struct stream* strm = ev->ctx;
	  struct connect* conn = strm->conn;
	  lua_State* T = strm->T;
		ssize_t len;

		// write event fired, let's do some writing
    len = write(ev->fd, &strm->io_buf[strm->io_idx], (strm->io_len - strm->io_idx));

		// writing returned an error, log it and check if it's recovarable
	  if (len < 0) {
			  log_dbg(5, "errno: %s", strerror(errno));
			  if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
			      return;
				}
				// handle some fs error
		// we wrote some data, check if we're done writing and add it to the lua buffer
	  } else {
				if ((strm->io_idx += len) < strm->io_len)
			      return;
	  }

		// remove event from firing - we wrote all the data
		EQ_DEL(conn->thr->eq, &strm->ev, ev->fd, EV_WRITE);

		// signal we're no longer blocked by lua
		strm->ss ^= SS_WAIT;

    // reset event counters
    strm->io_idx = 0;
    strm->io_len = 0;

		// resume lua execution with the complete event data on the lua stack
    if ((strm->lua_status = lua_run(T, strm->L, 0)) == 0)
		    lthread_remove(strm->L, &strm->T);

		// check for new lua blocking before resuming connection
		if (!(strm->ss & SS_WAIT))
		    return conn_resume(strm);
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
	  struct stream* strm;
		int len;

		log_dbg(5, "LUA_READ");

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
		lua_pushlightuserdata(L, L);
		lua_gettable(L, LUA_REGISTRYINDEX);
		strm = (struct stream*) lua_touserdata(L, -1);
		lua_pop(L, 1);

		// reset counters
		strm->io_idx = 0;
		strm->io_len = 0;

		// if first argument is nil, we're reading data from the connection
		if (lua_isnil(L, 1)) {
				if (strm->http_method == GET) {
					  log_dbg(5, "lua_read: cannot read from connection during GET method");
						return 0;
				}
			  strm->io_len = len;

				strm->ss = SS_RECV;
		// argument is a lua FILE structure, get it's file descriptor and add it to the event queue
    } else {
			  struct aio_data *aio_d;
			  FILE* f;
				long int idx;
				int fd;
				int found = 0;

				// grab the FILE structure from lua
				f = *(FILE**) luaL_checkudata(L, 1, LUA_FILEHANDLE);

				// attempt to find an existing open file handle
				//SIMPLEQ_FOREACH(aio_d, &strm->aio_d, next) {
				LIST_FOREACH(aio_d, &strm->aio_d, next) {
					  if (aio_d->f == f) {
								found = 1;

								if ((aio_d->pos >= aio_d->flen) && (aio_d->ready> 0)) {
    								LIST_REMOVE(aio_d, next);
										return 0;
								}
								break;
						}
				}

				// it's a new file stream, init and get stats
				if (found == 0) {
						struct stat st;

						// alloc memory for aio struct
						aio_d = calloc(1, sizeof(struct aio_data));

						// check is malloc succeeded
 						if (aio_d == NULL)
						    return luaL_error(L, "malloc error");

						// retreive the corresponding file descriptor from the FILE structure
						if ((aio_d->fd = fileno(f)) < 0)
								return luaL_error(L, "invalid file descriptor associated with lua stream");

						aio_d->f = f;
						aio_d->buf = strm->io_buf; //aio_d->buf = NULL;
						aio_d->ctx = strm;

						// get value of position indicator for the lua FILE
						aio_d->pos = ftell(f);

						// if the returned position is valid, calculate file size so we can stet up AIO reads
						if (aio_d->pos >= 0) {
								fstat(aio_d->fd, &st);
								aio_d->flen = st.st_size;
								//fcntl(aio_d->fd, F_SETFL, fcntl(aio_d->fd, F_GETFL, 0) | O_DIRECT); // why does this break it?

						} else {
						    // it's a FIFO stream, set it to non-blocking before adding it to the event system
						    fcntl(aio_d->fd, F_SETFL, fcntl(aio_d->fd, F_GETFL, 0) | O_NONBLOCK);
						}



						// add it to the queue
						//SIMPLEQ_INSERT_TAIL(&strm->aio_d, aio_d, next);
						LIST_INSERT_HEAD(&strm->aio_d, aio_d, next);
				}

				// set up a lua buffer to use for our read events
				luaL_buffinit(L, &strm->lb);

				if (aio_d->pos >= 0) {
					  // struct stat st;
					  //fstat(fileno(f), &st);
					  //aio_d->flen = st.st_size;
						aio_d->len = MIN((aio_d->flen - aio_d->pos), len);
						strm->io_len = aio_d->len;
						if (aio_d->len <= 0)
						    return 0;

						schedule_aio_read(strm->conn->thr->aio, aio_d);
				} else {
				    aio_d->len = len;
						strm->io_len = len;
						EQ_ADD(strm->conn->thr->eq, &strm->ev, aio_d->fd, EV_READ, strm_read, strm, 0);
				}

				// flag that we need to wait for ready event
				strm->ss |= SS_WAIT;
		}
		// yield lua coroutine
		return lua_yield(L, 0);
}


static int
lua_write(lua_State *L)
{
	  struct stream* strm;
	  struct connect *conn;
		const char* buf;

		// check that the function is called with the right number of arguments
		if (lua_gettop(L) != 2) {
        log_ex(NULL, 1, "httpd.write expects exactly 2 arguments");
			  return 0;
		}

		// check that buffer size is a number
		if (lua_type(L, 2) != LUA_TSTRING) {
				log_dbg(5, "httpd.write: value not a string");
				return 0;
		}

		// grab the strm stucture corresponding with the lua context
		lua_pushlightuserdata(L, L);
		lua_gettable(L, LUA_REGISTRYINDEX);
		strm = (struct stream*) lua_touserdata(L, -1);
		lua_pop(L, 1);

		// reset counters
		strm->io_idx = 0;
		strm->io_len = 0;

		// if first argument is nil, we're writing data into the connection
		if (lua_isnil(L, 1)) {
			  if ((strm->http_method == POST) && (strm->not_found == 0)) {
				    log_dbg(5, "lua_write: cannot write into connection during POST method");
					  return 0;
				}

				strm->io_buf = (char*) lua_tolstring(L, 2, &strm->io_len);

				// flag that stream has data to send
			  strm->ss = SS_SEND;

		// argument is a lua FILE structure, get it's file descriptor and add it to the event queue
    } else {
	      FILE* f;
				int fd;
				struct aio_data *aio_d;
				long int pos;
				int found = 0;

				// grab the file structure from lua
				f = *(FILE**) luaL_checkudata(L, 1, LUA_FILEHANDLE);

				// attempt to find an existing open file handle
				//SIMPLEQ_FOREACH(aio_d, &strm->aio_d, next) {
				LIST_FOREACH(aio_d, &strm->aio_d, next) {
						if (aio_d->f == f) {
								found = 1;
								break;
						}
				}

				// it's a new file stream, init and get stats
				if (found == 0) {
						struct stat st;

						// alloc memory for aio struct
						aio_d = calloc(1, sizeof(struct aio_data));

						// check is malloc succeeded
						if (aio_d == NULL)
								return luaL_error(L, "malloc error");

						// retreive the corresponding file descriptor from the FILE structure
						if ((aio_d->fd = fileno(f)) < 0)
								return luaL_error(L, "invalid file descriptor associated with lua stream");

						aio_d->f = f;
						aio_d->ctx = strm;

						// get value of position indicator for the lua FILE
						aio_d->pos = ftell(f);

						// if the returned position is valid, calculate file size so we can stet up AIO reads
						if (aio_d->pos >= 0) {
								//fcntl(aio_d->fd, F_SETFL, fcntl(aio_d->fd, F_GETFL, 0) | O_DIRECT); // why does this break it, bug?
						} else
								// it's a FIFO stream, set it to non-blocking before adding it to the event system
								fcntl(aio_d->fd, F_SETFL, fcntl(aio_d->fd, F_GETFL, 0) | O_NONBLOCK);

						// add it to the queue
						//SIMPLEQ_INSERT_TAIL(&strm->aio_d, aio_d, next);
						LIST_INSERT_HEAD(&strm->aio_d, aio_d, next);
				}

				// get the lua string and its size
				strm->io_buf = (char*) lua_tolstring(L, 2, &strm->io_len);
				aio_d->buf = strm->io_buf; //aio_d->buf = NULL;
				aio_d->len = strm->io_len;

				if (aio_d->pos >= 0) {
						if (aio_d->len <= 0)
								return 0;
						schedule_aio_write(strm->conn->thr->aio, aio_d);
				} else {
						// add it to the event queue to fire when write ready
						EQ_ADD(strm->conn->thr->eq, &strm->ev, aio_d->fd, EV_WRITE, strm_write, strm, 0);
				}

				// flag that we need to wait for ready event
				strm->ss |= SS_WAIT;
		}
		// yield lua coroutine
    return lua_yield(L, 1);
}

static int
lua_header(lua_State *L)
{
	  struct stream* strm;

		// check that the function is called with the right number of arguments
		if (lua_gettop(L) != 1) {
				log_ex(NULL, 1, "httpd.header: expects exactly 1 argument");
				return 0;
		}

		lua_pushlightuserdata(L, L);
		lua_gettable(L, LUA_REGISTRYINDEX);
		strm = (struct stream*) lua_touserdata(L, -1);

		lua_pop(L, 1);
    lua_pushnil(L);

		strm->ss = SS_HEAD;

		stack_dump(L, "TTTTTJJ");
		return lua_yield(L, 2);
} //f

static int
luaopen_httpd(lua_State *L)
{
	  struct luaL_Reg functions[] = {
		    { "read",		lua_read },
		    { "register_handler",	register_handler },
		    { "write",		lua_write },
		    { "header",  lua_header},
		    { NULL, NULL }
	  };

#if LUA_VERSION_NUM >= 502
		luaL_newlib(L, functions);
#else
	  luaL_register(L, "httpd", functions);
#endif

	  lua_pushstring(L, "httpd 1.0.0");
	  lua_setfield(L, -2, "_VERSION");
	  return 1;
}

int
//lua_map_create(struct thread* thr, const char *prefix, const char *script)
lua_map_create(struct thread* thr, struct l_map *l_map)
{
		struct lua_map *lm;

		SIMPLEQ_FOREACH(lm, l_map, next) {
			  struct lua_state_map* Lm;

			  if ((access(lm->script, F_OK) < 0))
					  return -1;

				if ((Lm = malloc(sizeof(struct lua_state_map))) == NULL)
				    return -1;

				while (*lm->prefix == '/')
						lm->prefix++;

				Lm->prefix = lm->prefix;
				Lm->script = lm->script;
				SIMPLEQ_INIT(&Lm->l_hand);
				//Lm->l_hand = NULL;

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
    struct lua_state_map* Lm;
    struct lua_handler* lh;
    struct thread* thr;

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

		log_dbg(5, "HERE: %s", lh->name);

		SIMPLEQ_INSERT_TAIL(&Lm->l_hand, lh, next);

	  return 0;
}

void
lh_aio_dispatch(struct aio_data *aio_d)
{
	  struct stream *strm = (struct stream *) aio_d->ctx;;
		int rv;
log_dbg(5, "YAYA");
stack_dump(strm->T, "DISPATCH");
log_dbg(5, "len %i buf: %s", aio_d->len, aio_d->buf);
log_dbg(5, "len %i buf: %s", strm->io_len, strm->io_buf);

		rv = aio_d->len;

		if (rv < 0) {
		    strm->ss = SS_ERROR;
				lua_pushnil(strm->T);
		} else if (aio_d->buf != NULL) {
				if (rv == 0)
						lua_pushnil(strm->T);
				else {
					  //lua_pushlstring(strm->T, acb->aio_buf, acb->aio_nbytes);
						log_dbg(5, "TT");
						lua_pushlstring(strm->T, aio_d->buf, rv);
				}
		}

		return strm_resume(strm);
}
