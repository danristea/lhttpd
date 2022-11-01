httpd = require 'httpd'


local function get_content_length(head)
    for k,v in pairs(head) do
        if string.lower(k) == "content-length" then
            return tonumber(v)
        end
    end
    return 0
end

local function save_to_file(len)
   local f = io.open("file.txt", "w")
   while (len > 0) do
       local data = httpd.read(nil, math.min(4,len))
       local x =  httpd.write(f, data)
       if not data then break end
       len = len - string.len(data)
   end
   f:close()
end

local function upload(env, head)

    local len = get_content_length(head)

    if (env["SERVER_PROTOCOL"] == "HTTP/2") then
        if (head[":method"] == "POST") then
            save_to_file(len)

            local h = {[":status"] = "200"}
            httpd.header(h)
        else
           local h = {[":status"] = "200", ["Content-Type"] = "text/html; charset=utf-8"}
           httpd.header(h)
           httpd.write(nil, "<h3>File upload service. Use POST</h3>")
        end
    else
        if (head["method"] == "POST") then
           save_to_file(len)

           local h = {["status"] = "200"}
           httpd.header(h)
        else
           local h = {["status"] = "200", ["Content-Type"] = "text/html; charset=utf-8"}
           httpd.header(h)
           httpd.write(nil, "<h3>File upload service. Use POST</h3>")
        end
    end
end

httpd.register_handler ("/upload", upload)
