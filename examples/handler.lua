httpd = require 'httpd'

local function handler(env, head)
    local h = {[":status"] = "200", ["Content-Type"] = "text/html; charset=utf-8"}

    httpd.header(h)

    httpd.write(nil, "<h3>Environment:</h3>")

    for k,v in pairs(env) do
        httpd.write(nil, k.." "..v.."<br/>")
    end

    httpd.write(nil, "<h3>Head:</h3>")

    for k,v in pairs(head) do
        httpd.write(nil, k.." "..v.."<br/>")
    end

end

httpd.register_handler ("/handler", handler)
