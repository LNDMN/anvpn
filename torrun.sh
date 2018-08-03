#!/bin/sh

_trans_port="9040"
_int_if="ppp+"

iptables -t nat -A PREROUTING -i $_int_if -p udp --dport 53 -j REDIRECT --to-ports 53
iptables -t nat -A PREROUTING -i $_int_if -p tcp --syn -j REDIRECT --to-ports $_trans_port

/etc/init.d/tor restart
