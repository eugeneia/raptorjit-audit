# Birdwatch

Auditlog and VMProfile explorer for Snabb.

Currently requires LuaJIT 2.1.

`audit/` contains a standalone LuaJIT module to read out Auditlog and VMProfile data.

## Usage

`make systemd_install_units` installs two systemd `--user` units:

```sh
# Periodically snapshot VMprofiles of running Snabb processes
# to ~/birdwatch-snapshots (this is optional)
$ systemctl --user enable birdwatch-snap.timer
$ systemctl --user start birdwatch-snap.timer
# Generate reports on http://localhost:8077
$ systemctl --user enable birdwatch.socket
$ systemctl --user start birdwatch.socket
```

You can also generate reports manually:

```sh
# Generate summary report for PID 1234
$ ./birdwatch report /1234 > 1234.html
# Generate detailed trace report for trace 42 of PID 1234
$ ./birdwatch report /1234/trace/42 > 1234-42.html
```