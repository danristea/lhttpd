httpd = require 'httpd'

local i = 0

local function state(env, head)
    local h = {[":status"] = "200", ["Content-Type"] = "text/html; charset=utf-8"}

    httpd.header(h)

    httpd.write(nil, "<h3>counter: "..i.."</h3>")
    i = i + 1
end

httpd.register_handler ("/state", state)

