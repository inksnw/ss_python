#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import socket
from shadowsocks import common, lru_cache, eventloop

QTYPE_ANY = 255
QTYPE_A = 1
QTYPE_AAAA = 28
QTYPE_CNAME = 5
QTYPE_NS = 2
QCLASS_IN = 1


class DNSResolver(object):
    """docstring for DNSResolver"""

    def __init__(self, server_list=None, prefer_ipv6=False):
        self._loop = None
        self._hosts = {}
        self._hostname_status = {}
        self._hostname_to_cb = {}
        self._cb_to_hostname = {}

        self._cache = lru_cache.LRUCache(timeout=300)
        self._sock = None
        if server_list is None:
            self._servers = None
            self._parse_resolv()
        else:
            self._servers = server_list
        if prefer_ipv6:
            self._QTYPES = [QTYPE_AAAA, QTYPE_A]
        else:
            self._QTYPES = [QTYPE_A, QTYPE_AAAA]
        self._parse_hosts()
        # TODO monitor hosts change and reload hosts
        # TODO parse /etc/gai.conf and follow its rules

    def _parse_resolv(self):
        self._servers = []
        try:
            with open('/etc/resolv.conf', 'rb') as f:
                content = f.readlines()
                for line in content:
                    line = line.strip()
                    if not (line and line.startswith(b'nameserver')):
                        continue

                    parts = line.split()
                    if len(parts) < 2:
                        continue

                    server = parts[1]
                    if common.is_ip(server) == socket.AF_INET:
                        if type(server) != str:
                            server = server.decode('utf8')
                        self._servers.append(server)
        except IOError:
            pass
        if not self._servers:
            self._servers = ['8.8.4.4', '8.8.8.8']

    def _parse_hosts(self):
        etc_path = '/etc/hosts'
        if 'WINDIR' in os.environ:
            etc_path = os.environ['WINDIR'] + '/system32/drivers/etc/hosts'
        try:
            with open(etc_path, 'rb') as f:
                for line in f.readlines():
                    line = line.strip()
                    parts = line.split()
                    if len(parts) < 2:
                        continue

                    ip = parts[0]
                    if not common.is_ip(ip):
                        continue

                    for i in range(1, len(parts)):
                        hostname = parts[i]
                        if hostname:
                            self._hosts[hostname] = ip
        except IOError:
            self._hosts['localhost'] = '127.0.0.1'

    def add_to_loop(self, loop):
        if self._loop:
            raise Exception('already add to loop')
        self._loop = loop
        # TODO when dns server is IPv6
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM,
                                   socket.SOL_UDP)
        self._sock.setblocking(False)
        loop.add(self._sock, eventloop.POLL_IN, self)
        loop.add_periodic(self.handle_periodic)

    def _call_callback(self, hostname, ip, error=None):
        callbacks = self._hostname_to_cb.get(hostname, [])
        for callback in callbacks:
            if callback in self._cb_to_hostname:
                del self._cb_to_hostname[callback]
            if ip or error:
                callback((hostname, ip), error)
            else:
                callback((hostname, None),
                         Exception('unknown hostname %s' % hostname))
        if hostname in self._hostname_to_cb:
            del self._hostname_to_cb[hostname]
        if hostname in self._hostname_status:
            del self._hostname_status[hostname]

    def _handle_data(self, data):
        response = parse_response(data)
        if response and response.hostname:
            hostname = response.hostname
            ip = None
            for answer in response.answers:
                if answer[1] in (QTYPE_A, QTYPE_AAAA) and \
                        answer[2] == QCLASS_IN:
                    ip = answer[0]
                    break
            if not ip and self._hostname_status.get(hostname, STATUS_SECOND) \
                    == STATUS_FIRST:
                self._hostname_status[hostname] = STATUS_SECOND
                self._send_req(hostname, self._QTYPES[1])
            else:
                if ip:
                    self._cache[hostname] = ip
                    self._call_callback(hostname, ip)
                elif self._hostname_status.get(hostname, None) \
                        == STATUS_SECOND:
                    for question in response.questions:
                        if question[1] == self._QTYPES[1]:
                            self._call_callback(hostname, None)
                            break

    def handle_event(self, sock, fd, event):
        if sock != self._sock:
            return
        if event & eventloop.POLL_ERR:
            logging.error('dns socket err')
            self._loop.remove(self._sock)
            self._sock.close()
            # TODO when dns server is IPv6
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM,
                                       socket.SOL_UDP)
            self._sock.setblocking(False)
            self._loop.add(self._sock, eventloop.POLL_IN, self)
        else:
            data, addr = sock.recvfrom(1024)
            if addr[0] not in self._servers:
                logging.warn('received a packet other than our dns')
                return
            self._handle_data(data)

    def handle_periodic(self):
        self._cache.sweep()

    def remove_callback(self, callback):
        hostname = self._cb_to_hostname.get(callback)
        if hostname:
            del self._cb_to_hostname[callback]
            arr = self._hostname_to_cb.get(hostname, None)
            if arr:
                arr.remove(callback)
                if not arr:
                    del self._hostname_to_cb[hostname]
                    if hostname in self._hostname_status:
                        del self._hostname_status[hostname]

    def _send_req(self, hostname, qtype):
        req = build_request(hostname, qtype)
        for server in self._servers:
            logging.debug('resolving %s with type %d using server %s',
                          hostname, qtype, server)
            self._sock.sendto(req, (server, 53))

    def resolve(self, hostname, callback):
        if type(hostname) != bytes:
            hostname = hostname.encode('utf8')
        if not hostname:
            callback(None, Exception('empty hostname'))
        elif common.is_ip(hostname):
            callback((hostname, hostname), None)
        elif hostname in self._hosts:
            logging.debug('hit hosts: %s', hostname)
            ip = self._hosts[hostname]
            callback((hostname, ip), None)
        elif hostname in self._cache:
            logging.debug('hit cache: %s', hostname)
            ip = self._cache[hostname]
            callback((hostname, ip), None)
        else:
            if not is_valid_hostname(hostname):
                callback(None, Exception('invalid hostname: %s' % hostname))
                return
            arr = self._hostname_to_cb.get(hostname, None)
            if not arr:
                self._hostname_status[hostname] = STATUS_FIRST
                self._send_req(hostname, self._QTYPES[0])
                self._hostname_to_cb[hostname] = [callback]
                self._cb_to_hostname[callback] = hostname
            else:
                arr.append(callback)
                # TODO send again only if waited too long
                self._send_req(hostname, self._QTYPES[0])

    def close(self):
        if self._sock:
            if self._loop:
                self._loop.remove_periodic(self.handle_periodic)
                self._loop.remove(self._sock)
            self._sock.close()
            self._sock = None
