#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2015 clowwindy


import sys
import os
import logging
import signal

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../'))
from shadowsocks import utils, eventloop, tcprelay, asyncdns


def main():

    config = utils.get_config()
    dns_resolver = asyncdns.DNSResolver(prefer_ipv6=config['prefer_ipv6'])
    tcp_server = tcprelay.TCPRelay(config, dns_resolver, False)

    loop = eventloop.EventLoop()
    dns_resolver.add_to_loop(loop)
    tcp_server.add_to_loop(loop)
    loop.run()


if __name__ == '__main__':
    main()
