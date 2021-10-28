#!/bin/sh

cat <<EOF
[Unit]
Description=Birdwatch responder

[Service]
Environment="PATH=/usr/bin"
Environment="HOME=%h"
#ExecStart=-$(pwd)/birdwatch socket-activate
ExecStart=$(pwd)/birdwatch socket-activate
StandardInput=socket
EOF
