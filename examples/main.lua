httpd = require 'httpd'

local function js(env, head)
    local h = {[":status"] = "200"}
    httpd.header(h)

    httpd.write(nil, "window.onload = function get_body() {body = document.getElementsByTagName('body')[0]; body.innerHTML+= '<div>Javascript loaded.</div>'}")
end

local function p1(env, head)
    local h = {[":status"] = "200"}
    httpd.header(h)

    local f = io.open("/pub/webui/p1.png", "r")

    while true do
        local data = httpd.read(f, 4096)
        if not data then break end
        httpd.write(nil, data)
    end

end

local function p2(env, head)
    local h = {[":status"] = "200"}
    httpd.header(h)

    local f = io.open("/pub/webui/p2.png", "r")

    while true do
        local data = httpd.read(f, 4096)
        if not data then break end
        httpd.write(nil, data)
    end

end

local function p3(env, head)
    local h = {[":status"] = "200"}
    httpd.header(h)

    local f = io.open("/pub/webui/p3.png", "r")

    while true do
        local data = httpd.read(f, 4096)
        if not data then break end
        httpd.write(nil, data)
    end

end

local function main(env, head)

    -- main headers
    local h = {[":status"] = "200"}
    httpd.header(h)

    local body ="<!DOCTYPE html><html><head><script src='/js'></script><title>Page Title</title></head><body><h1>Some Heading</h1><p>Some paragraph.</p><img src='/p1' alt='image1' /><img src='/p2' alt='image2' /><img src='/p3' alt='image3' /></body></html>"
    httpd.write(nil, body)

end

local function notfound(env, head)
    local body = '<!DOCTYPE html>\n<html>\n<head>\n<meta http-equiv="Content-Type" content="text/html; charset=utf-8"/>\n<title>404 Not Found</title>\n</head><body><h1>404 Not Found</h1><hr></body></html>'
    local head = {[":status"] = "404", ["Content-length"] = string.len(body)}

    httpd.header(head)
    httpd.write(nil, body)

end

httpd.register_handler("/", main)
httpd.register_handler("/notfound", notfound)
httpd.register_handler("/js", js)
httpd.register_handler("/p1", p1)
httpd.register_handler("/p2", p2)
httpd.register_handler("/p3", p3)
