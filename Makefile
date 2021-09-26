LUA_PATH = "./?/init.lua;;"

test:
	LUA_PATH=$(LUA_PATH) luajit test/snabb-basic1.lua

birdwatch:
	LUA_PATH=$(LUA_PATH) luajit birdwatch.lua

.PHONY: test birdwatch
