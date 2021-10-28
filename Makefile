LUA_PATH = "./?/init.lua;;"

test:
	LUA_PATH=$(LUA_PATH) luajit test/snabb-basic1.lua

birdwatch:
	LUA_PATH=$(LUA_PATH) luajit birdwatch.lua

systemd_install_units: systemd/birdwatch.socket systemd/birdwatch@.service.sh
	mkdir -p ~/.config/systemd/user
	cp systemd/birdwatch.socket ~/.config/systemd/user/
	systemd/birdwatch@.service.sh > ~/.config/systemd/user/birdwatch@.service
	cp systemd/birdwatch-snap.timer ~/.config/systemd/user/
	systemd/birdwatch-snap.service.sh > ~/.config/systemd/user/birdwatch-snap.service

.PHONY: test birdwatch systemd_install
