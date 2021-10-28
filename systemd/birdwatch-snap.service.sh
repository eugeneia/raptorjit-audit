#!/bin/sh

cat <<EOF
[Unit]
Description=Birdwatch Snapshotter

[Service]
Environment="PATH=/usr/bin"
Environment="HOME=%h"
ExecStart=$(pwd)/birdwatch snap
EOF
