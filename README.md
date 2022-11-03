# lhttpd

## Overview

**lhttpd** is a secure multithreaded HTTP/1.x HTTP/2 webserver written in C designed to execute lua bytecode in a non-blocking fashion via its API functions. It uses [bearssl](https://bearssl.org/) for secure communication and AIO (in-kernel support) for asynchronous disk I/O. It supports both versions of lua and luajit, has been tested on Linux and FreeBSD and is ideal for embedded environments.

## Architectural Notes

The server component is designed to run on multiple POSIX threads (pthreads) in a nonblocking and lockless (no mutex) fashion. It achieves this by interlacing the OS event system (kqueue, epoll) with lua coroutines via its custom API functions. States are kept thread specific with the server socket armed with one-shot and re-armed by next thread’s syscall of batched events as applicable. New connection memory allocation is pre-allocated per-thread when cycles permit, before a new connection event is ready. Asynchronous I/O requests are also batched per syscall, as applicable. Memory management is kept to minimum on the server side, and stream (API) specific memory management needed for connection and AIO communication is hooked into Lua’s garbage collection.

## API 

Before a Lua function can be executed by a request, it needs to be registered at the start via the function call httpd.register_handler(name, function). The name needs to start with “/“ and is the keyword that matches a request’s path after a prefix is found.

The registered function needs to have 2 table arguments that are populated at the request execution with the environment variables and the request variables respectively.


API Server can be started with the following parameters:

    progname [-l lua prefix, lua script] [-c certifiate] [-k private key] [options] 
    options: 
    -l lua prefix, lua script : associate lua prefix name with execution of lua script (multiple prefix/script mappings can be provided) 
    -u user : username to run the server as -a address : IP address to bind to 
    -p port : port to bind to 
    -r rootdir : provide root directory to chroot into 
    -d (enable debuging) : turn on verbose logging 
    -f (foreground mode) : helpful for debugging

The following API functions are provided:

    httpd.register_handler("/name", function) - functions that registers a handler name (must start with "/") with a coresponding lua function
    httpd.header(lua_table) - function that takes a lua table with response header key/value pairs which are converted into HTTP headers and sent over to the client
    httpd.read(stream, length) - function that takes a lua stream (result of io.open/io.popen) or nil (if reading directly from the connection via client POST) and the length of how much. it returns a string, or nil if EOF 
    httpd.write(stream, string) - function that takes a lua stream (result of io.open/io.popen) or nil (if writing directly to the connection) and the string to be written.

To be able to invoke functions within a lua script via HTTP requests, the following steps need to be present:

- a prefix name must be associated with a lua script name as a parameter during server startup (eg. -l prefix script.lua)
- httpd = require 'httpd' - this line must be present inside the lua script; it loads the custom lua library API functions described below
- httpd.register_handler('bar', foo) - this register the function foo as a handler "bar" executed when URI matches "/name/bar"
- local function foo(env, header) needs to be present with 2 tables (env and header) as function arguments that contain environent and request information

A minimal example: 

    httpd = require 'httpd'

    local function foo(env, header) 
        local head = {[":status"] = "200"} 
        httpd.header(head)

        for n,v in pairs(env) do
            httpd.write(nil, n.." "..v.."\n")
        end
        for n,v in pairs(header) do
            httpd.write(nil, n.." "..v.."\n")
        end
    end

    httpd.register_handler("/bar", foo)
    
 Additional examples can be found in the "examples" folder, which include upload, HTTP/2 server push, and more.
 
 ## Build Requirements:
 lhttpd is compiled using [lua](https://www.lua.org) or [luajit](https://luajit.org/), [bearssl](https://bearssl.org/) and [hpack](https://github.com/reyk/hpack).
 
 
