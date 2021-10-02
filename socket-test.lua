-- systemd-socket-activate -l 8080 -a --inetd $PWD/socket-test.sh
local get = io.stdin:read("l")
assert(get:match("^GET"))
local hello = "Hello, World!"
print("HTTP/1.1 200 OK\r")
print("Content-Type: text/html\r")
--print(("Content-Length: %d\r"):format(#hello))
print("\r")
print(hello)
