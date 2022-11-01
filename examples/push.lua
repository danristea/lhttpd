httpd = require 'httpd'

local function pp(env, head)
    local h = {[":status"] = "200"}
    httpd.header(h)

    httpd.write(nil, "window.onload = function get_body() {body = document.getElementsByTagName('body')[0]; body.innerHTML+= '<div>Javascript loaded.</div>'}")
end

local function p1(env, head)
    local h = {[":status"] = "200"}
    httpd.header(h)

    local f = io.open("/root/webui/p1.png", "r")

    while true do
        local data = httpd.read(f, 4096)
        if not data then break end
        httpd.write(nil, data)
    end

end

local function p2(env, head)
    local h = {[":status"] = "200"}
    httpd.header(h)

    local f = io.open("/root/webui/p2.png", "r")

    while true do
        local data = httpd.read(f, 4096)
        if not data then break end
        httpd.write(nil, data)
    end

end

local function p3(env, head)
    local h = {[":status"] = "200"}
    httpd.header(h)

    local f = io.open("/root/webui/p3.png", "r")

    while true do
        local data = httpd.read(f, 4096)
        if not data then break end
        httpd.write(nil, data)
    end

end

local function push(env, head)

    --check if client supports it before we start sending promise headers
    if env["PUSH_PROMISE"] then
        local ph
        ph = {[":method"] = "GET", [":authority"] = head[":authority"], [":scheme"] = "https", [":path"] = "/pp"}
        httpd.header(ph)
        ph = {[":method"] = "GET", [":authority"] = head[":authority"], [":scheme"] = "https", [":path"] = "/p1"}
        httpd.header(ph)
        ph = {[":method"] = "GET", [":authority"] = head[":authority"], [":scheme"] = "https", [":path"] = "/p2"}
        httpd.header(ph)
        ph = {[":method"] = "GET", [":authority"] = head[":authority"], [":scheme"] = "https", [":path"] = "/p3"}
        httpd.header(ph)
    end

    -- main headers
    local h = {[":status"] = "200"}
    httpd.header(h)

    local body ="<!DOCTYPE html><html><head><script src='/pp'></script><title>Page Title</title></head><body><h1>Some Heading</h1><p>Some paragraph.</p><img src='/p1' alt='image1' /><img src='/p2' alt='image2' /><img src='/p3' alt='image3' /></body></html>"
    httpd.write(nil, body)

end

httpd.register_handler("/pp", pp)
httpd.register_handler("/p1", p1)
httpd.register_handler("/p2", p2)
httpd.register_handler("/p3", p3)
httpd.register_handler("/push", push)
