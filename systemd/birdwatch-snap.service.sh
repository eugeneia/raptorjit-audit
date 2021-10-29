#!/bin/sh

cat <<EOF
[Unit]
Description=Birdwatch Snapshotter
StartLimitIntervalSec=5
StartLimitBurst=10

[Service]
Environment="PATH=/usr/bin"
Environment="HOME=%h"
ExecStart=$(pwd)/birdwatch snap
EOF
