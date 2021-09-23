LUA_PATH = "./?/init.lua;;"

test:
	LUA_PATH=$(LUA_PATH) luajit test/snabb-basic1.lua

.PHONY: test
