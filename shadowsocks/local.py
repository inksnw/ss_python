#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import sys
import logging
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../'))
from shadowsocks import utils, tcprelay, eventloop


def main():
    config = utils.get_config()
    logging.info(f"starting local at {config['local_address']}:{config['local_port']}")

    tcp_server = tcprelay.TCPRelay(config, None, True)
    loop = eventloop.EventLoop()
    tcp_server.add_to_loop(loop)
    loop.run()


if __name__ == '__main__':
    main()
