#!/usr/bin/env python
# -*- coding: utf-8 -*-
import utils


def main():
    config = utils.get_config()
    logging.info("starting local at %s:%d" % (config['local_address'], config['local_port']))

    dns_resolver = asyncdns.DNSResolver()
    tcp_server = tcprelay.TCPRelay(config, dns_resolver, True)
    udp_server = udprelay.UDPRelay(config, dns_resolver, True)
    loop = eventloop.EventLoop()
    dns_resolver.add_to_loop(loop)
    tcp_server.add_to_loop(loop)
    udp_server.add_to_loop(loop)

    loop.run()


if __name__ == '__main__':
    main()
