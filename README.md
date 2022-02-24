# lhttpd

lhttpd - multithreaded webserver written in C that executes lua/luajit bytecode. It supports ssl encryption (via bearssl) and minimal HTTP1.x/HTTP/2 protocols implementation.
It featues a custom API designed to be non-blocking by utilizing lua coroutines interleaved with async I/O calls via an event system. AIO (in-kernel support) is used for file read/write operations.  

API
Server can be started with the following parameters:
[-l lua prefix, lua script] [-c certifiate] [-k private key] [options]
options:
-l lua prefix, lua script : associate lua prefix name with execution of lua script (multiple prefix/script mappings can be provided)
-u user : username to run the server as
-a address : IP address to bind to
-p port : port to bind to
-r rootdir : provide root directory to chroot into
-d (enable debuging) : turn on verbose logging
-f (foreground mode) : helpful for debugging

To be able to invoke functions within a lua script via HTTP requests, the following steps need to be present:
1) a prefix name must be associated with a lua script name as a parameter during server startup (eg. -l prefix script.lua)
2) httpd = require 'httpd' - this line must be present inside the lua script; it loads the custom lua library API functions described below
API functions:
3) httpd.register_handler('bar', foo) -> this register the function foo as a handler "bar" executed when URI contains the "name/bar"
4) local function foo(env, header) needs to be present with 2 tables (env and header) as function arguments that contain environent and request information


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

httpd.register_handler('bar', foo)
