#!/usr/bin/env python
# -*- coding: utf-8 -*-

import select
import time
import errno
import traceback
import utils
import logging
import socket
import os
from collections import defaultdict
# we check timeouts every TIMEOUT_PRECISION seconds
TIMEOUT_PRECISION = 10


POLL_NULL = 0x00
POLL_IN = 0x01
POLL_OUT = 0x04
POLL_ERR = 0x08
POLL_HUP = 0x10
POLL_NVAL = 0x20

EVENT_NAMES = {
    POLL_NULL: 'POLL_NULL',
    POLL_IN: 'POLL_IN',
    POLL_OUT: 'POLL_OUT',
    POLL_ERR: 'POLL_ERR',
    POLL_HUP: 'POLL_HUP',
    POLL_NVAL: 'POLL_NVAL',
}


class SelectLoop(object):
    """docstring for SelectLoop"""

    def __init__(self):
        self._r_list = set()
        self._w_list = set()
        self._x_list = set()

    def poll(self, timeout):
        r, w, x = select.select(self._r_list, self._w_list, self._x_list, timeout)
        results = defaultdict(lambda: POLL_NULL)
        for p in [(r, POLL_IN), (w, POLL_OUT), (x, POLL_ERR)]:
            for fd in p[0]:
                results[fd] |= p[1]
        return results.items()

    def register(self, fd, mode):
        if mode & POLL_IN:
            self._r_list.add(fd)
        if mode & POLL_OUT:
            self._w_list.add(fd)
        if mode & POLL_ERR:
            self._x_list.add(fd)

    def unregister(self, fd):
        if fd in self._r_list:
            self._r_list.remove(fd)
        if fd in self._w_list:
            self._w_list.remove(fd)
        if fd in self._x_list:
            self._x_list.remove(fd)

    def modify(self, fd, mode):
        self.unregister(fd)
        self.register(fd, mode)

    def close(self):
        pass


class EventLoop(object):
    """docstring for EventLoop"""

    def __init__(self):
        if hasattr(select, 'epoll'):
            self._impl = select.epoll()
            model = 'epoll'
        elif hasattr(select, 'select'):
            self._impl = SelectLoop()
            model = 'select'
        else:
            raise Exception('cant find any available functions in select package')
        self._fdmap = {}
        self._last_time = time.time()
        self._periodic_callbacks = []
        self._stopping = False
        logging.debug(f'using event model {model}')

    def poll(self, timeout=None):
        events = self._impl.poll(timeout)
        return [(self._fdmap[fd][0], fd, event) for fd, event in events]

    def add(self, f, mode, handler):
        fd = f.fileno()
        self._fdmap[fd] = (f, handler)
        self._impl.register(fd, mode)

    def remove(self, f):
        fd = f.fileno()
        del self._fdmap[fd]
        self._impl.unregister(fd)

    def add_periodic(self, callback):
        self._periodic_callbacks.append(callback)

    def remove_periodic(self, callback):
        self._periodic_callbacks.remove(callback)

    def modify(self, f, mode):
        fd = f.fileno()
        self._impl.modify(fd, mode)

    def stop(self):
        self._stopping = True

    def run(self):
        events = []

        while not self._stopping:
            asap = False
            try:
                events = self.poll(TIMEOUT_PRECISION)
            except (OSError, IOError) as e:
                if errno_from_exception(e) in (errno.EPIPE, errno.EINTR):
                    # EPIPE: Happens when the client closes the connection
                    # EINTR: Happens when received a signal
                    # handles them as soon as possible
                    asap = True
                    logging.debug(f'poll:{e}')
                else:
                    logging.error(f'poll:{e}')
                    traceback.print_exc()
                    continue
            for sock, fd, event in events:
                handler = self._fdmap.get(fd, None)
                if handler is not None:
                    handler = handler[1]
                    try:
                        handler.handle_event(sock, fd, event)
                    except (OSError, IOError) as e:
                        utils.print_exception(e)
            now = time.time()
            if asap or now - self._last_time >= TIMEOUT_PRECISION:
                for callback in self._periodic_callbacks:
                    callback()
                self._last_time = now

    def __del__(self):
        self._impl.close()


# from tornado

def errno_from_exception(e):
    """Provides the errno from an Exception object.

    There are cases that the errno attribute was not set so we pull
    the errno out of the args but if someone instatiates an Exception
    without any args you will get a tuple error. So this function
    abstracts all that behavior to give you a safe way to get the
    errno.
    """

    if hasattr(e, 'errno'):
        return e.errno
    elif e.args:
        return e.args[0]
    else:
        return None
# from tornado


def get_sock_error(sock):
    error_number = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
    return socket.error(error_number, os.strerror(error_number))
