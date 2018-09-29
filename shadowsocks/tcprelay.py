import time
import utils
import logging
import errno
import random
# we clear at most TIMEOUTS_CLEAN_SIZE timeouts each time
TIMEOUTS_CLEAN_SIZE = 512

MSG_FASTOPEN = 0x20000000

# SOCKS METHOD definition
METHOD_NOAUTH = 0

# SOCKS command definition
CMD_CONNECT = 1
CMD_BIND = 2
CMD_UDP_ASSOCIATE = 3

# for each opening port, we have a TCP Relay

# for each connection, we have a TCP Relay Handler to handle the connection

# for each handler, we have 2 sockets:
#    local:   connected to the client
#    remote:  connected to remote server

# for each handler, it could be at one of several stages:

# as sslocal:
# stage 0 auth METHOD received from local, reply with selection message
# stage 1 addr received from local, query DNS for remote
# stage 2 UDP assoc
# stage 3 DNS resolved, connect to remote
# stage 4 still connecting, more data from local received
# stage 5 remote connected, piping local and remote

# as ssserver:
# stage 0 just jump to stage 1
# stage 1 addr received from local, query DNS for remote
# stage 3 DNS resolved, connect to remote
# stage 4 still connecting, more data from local received
# stage 5 remote connected, piping local and remote

STAGE_INIT = 0
STAGE_ADDR = 1
STAGE_UDP_ASSOC = 2
STAGE_DNS = 3
STAGE_CONNECTING = 4
STAGE_STREAM = 5
STAGE_DESTROYED = -1

# for each handler, we have 2 stream directions:
#    upstream:    from client to server direction
#                 read local and write to remote
#    downstream:  from server to client direction
#                 read remote and write to local

STREAM_UP = 0
STREAM_DOWN = 1

# for each stream, it's waiting for reading, or writing, or both
WAIT_STATUS_INIT = 0
WAIT_STATUS_READING = 1
WAIT_STATUS_WRITING = 2
WAIT_STATUS_READWRITING = WAIT_STATUS_READING | WAIT_STATUS_WRITING

BUF_SIZE = 32 * 1024
UP_STREAM_BUF_SIZE = 16 * 1024
DOWN_STREAM_BUF_SIZE = 32 * 1024

# helper exceptions for TCPRelayHandler


class BadSocksHeader(Exception):
    pass


class NoAcceptableMethods(Exception):
    pass


class TCPRelayHandler(object):
    """docstring for TCPRelayHandler"""

    def __init__(self, server, fd_to_handler, loop, local_sock, config,
                 dns_resolver, is_local):
        self._server = server
        self._fd_to_handlers = fd_to_handler
        self._loop = loop
        self._local_sock = local_sock
        self._remote_sock = None
        self._config = config
        self._dns_resolver = dns_resolver
        self.tunnel_remote = config.get('tunnel_remote', '8.8.8.8')
        self.tunnel_remote_port = config.get('tunnel_remote_port', 53)
        self.tunnel_port = config.get('tunnel_port', 53)
        self._is_tunnel = server._is_tunnel

        # TCP Relay works as either sslocal or ssserver
        # if is_local, this is sslocal
        self._is_local = is_local
        self._stage = STAGE_INIT
        self._cryptor = cryptor.Cryptor(config['password'],
                                        config['method'],
                                        config['crypto_path'])
        self._ota_enable = config.get('one_time_auth', False)
        self._ota_enable_session = self._ota_enable
        self._ota_buff_head = b''
        self._ota_buff_data = b''
        self._ota_len = 0
        self._ota_chunk_idx = 0
        self._fastopen_connected = False
        self._data_to_write_to_local = []
        self._data_to_write_to_remote = []
        self._upstream_status = WAIT_STATUS_READING
        self._downstream_status = WAIT_STATUS_INIT
        self._client_address = local_sock.getpeername()[:2]
        self._remote_address = None
        self._forbidden_iplist = config.get('forbidden_ip')
        if is_local:
            self._chosen_server = self._get_a_server()
        fd_to_handlers[local_sock.fileno()] = self
        local_sock.setblocking(False)
        local_sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
        loop.add(local_sock, eventloop.POLL_IN | eventloop.POLL_ERR,
                 self._server)
        self.last_activity = 0
        self._update_activity()

    def __hash__(self):
        # default __hash__ is id / 16
        # we want to eliminate collisions
        return id(self)

    @property
    def remote_address(self):
        return self._remote_address

    def _get_a_server(self):
        server = self._config['server']
        server_port = self._config['server_port']
        if isinstance(server_port, list):
            server_port = random.choice(server)
        if isinstance(server, list):
            server = random.choice(server)
        logging.debug(f'chosen server: {server}: {server_port}')
        return server, server_port

    def _update_activity(self, data_len=0):
        # tell the TCP Relay we have activities recently
        # else it will think we are inactive and timed out
        self._server.update_activity(self, data_len)

    def _update_stream(self, stream, status):
        # update a stream to a new waiting status

        # check if status is changed
        # only update if dirty
        dirty = False
        if stream == STREAM_DOWN:
            if self._downstream_status != status:
                self._downstream_status = status
                dirty = True
        elif stream == STREAM_UP:
            if self._upstream_status != status:
                self._upstream_status = status
                dirty = True
        if not dirty:
            return

        if self._local_sock:
            event = eventloop.POLL_ERR
            if self._downstream_status & WAIT_STATUS_WRITING:
                event |= eventloop.POLL_OUT
            if self._upstream_status & WAIT_STATUS_READING:
                event |= eventloop.POLL_IN
            self._loop.modify(self._local_sock, event)
        if self._remote_sock:
            event = eventloop.POLL_ERR
            if self._downstream_status & WAIT_STATUS_READING:
                event |= eventloop.POLL_IN
            if self._upstream_status & WAIT_STATUS_WRITING:
                event |= eventloop.POLL_OUT
            self._loop.modify(self._remote_sock, event)

    def _write_to_sock(self, data, sock):
        # write data to sock
        # if only some of the data are written, put remaining in the buffer
        # and update the stream to wait for writing
        if not data or not sock:
            return False
        uncomplete = False
        try:
            l = len(data)
            s = sock.send(data)
            if s < l:
                data = data[s:]
                uncomplete = True

        except (OSError, IOError) as e:
            error_no = eventloop.errno_from_exception(e)
            if error_no in (errno.EAGAIN, errno.EINPROGRESS,
                            errno.EWOULDBLOCK):
                uncomplete = True
            else:
                shell.print_exception(e)
                self.destroy()
                return False
        if uncomplete:
            if sock == self._local_sock:
                self._data_to_write_to_local.append(data)
                self._update_stream(STREAM_DOWN, WAIT_STATUS_WRITING)
            elif sock == self._remote_sock:
                self._data_to_write_to_remote.append(data)
                self._update_stream(STREAM_UP, WAIT_STATUS_WRITING)
            else:
                logging.error('write_all_to_sock:unknown socket')
        else:
            if sock == self._local_sock:
                self._update_stream(STREAM_DOWN, WAIT_STATUS_READING)
            elif sock == self._remote_sock:
                self._update_stream(STREAM_UP, WAIT_STATUS_READING)
            else:
                logging.error('write_all_to_sock:unknown socket')
        return True

    def _handle_stage_connecting(self, data):
        if not self._is_local:
            if self._ota_enable_session:
                self._ota_chunk_data(data, self._data_to_write_to_remote.append)
            else:
                self._data_to_write_to_remote.append(data)
            return
        if self._ota_enable_session:
            data = self._ota_chunk_data_gen(data)
        data = self._cryptor.encrypt(data)
        self._data_to_write_to_remote.append(data)

        if self._config['fast_open'] and not self._fastopen_connected:
            # for sslocal and fastopen, we basically wait for data and use
            # sendto to connect
            try:
                # only connect once
                self._fastopen_connected = True
                remote_sock = \
                    self._create_remote_socket(self._chosen_server[0],
                                               self._chosen_server[1])
                self._loop.add(remote_sock, eventloop.POLL_ERR, self._server)
                data = b''.join(self._data_to_write_to_remote)
                l = len(data)
                s = remote_sock.sendto(data, MSG_FASTOPEN,
                                       self._chosen_server)
                if s < l:
                    data = data[s:]
                    self._data_to_write_to_remote = [data]
                else:
                    self._data_to_write_to_remote = []
                self._update_stream(STREAM_UP, WAIT_STATUS_READWRITING)
            except (OSError, IOError) as e:
                if eventloop.errno_from_exception(e) == errno.EINPROGRESS:
                    # in this case data is not sent at all
                    self._update_stream(STREAM_UP, WAIT_STATUS_READWRITING)
                elif eventloop.errno_from_exception(e) == errno.ENOTCONN:
                    logging.error('fast open not supported on this OS')
                    self._config['fast_open'] = False
                    self.destroy()
                else:
                    shell.print_exception(e)
                    if self._config['verbose']:
                        traceback.print_exc()
                    self.destroy()

    def _handle_stage_addr(self, data):
        if self._is_local:
            if self._is_tunnel:
                # add ss header to data


class TCPRelay(object):
    """docstring for TCPRelay"""

    def __init__(self, config, dns_resolver, is_local, stat_callback=None):
        self._config = config
        self._is_local = is_local
        self._dns_resolver = dns_resolver
        self._closed = False
        self._eventloop = None
        self._fd_to_handlers = {}
        self._is_tunnel = False

        self._timeout = config['timeout']
        self._timeouts = []  # a list for all the handlers
        # we trim the timeouts once a while
        self._timeout_offset = 0   # last checked position for timeout
        self._handler_to_timeouts = {}  # key: handler value: index in timeouts

        if is_local:
            listen_addr = config['local_address']
            listen_port = config['local_port']
        else:
            listen_addr = config['server']
            listen_port = config['server_port']
        self._listen_port = listen_port

        addrs = socket.getaddrinfo(listen_addr, listen_port, 0,
                                   socket.SOCK_STREAM, socket.SOL_TCP)
        if len(addrs) == 0:
            raise Exception("can't get addrinfo for %s:%d" %
                            (listen_addr, listen_port))
        af, socktype, proto, canonname, sa = addrs[0]
        server_socket = socket.socket(af, socktype, proto)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(sa)
        server_socket.setblocking(False)
        if config['fast_open']:
            try:
                server_socket.setsockopt(socket.SOL_TCP, 23, 5)
            except socket.error:
                logging.error('warning: fast open is not available')
                self._config['fast_open'] = False
        server_socket.listen(1024)
        self._server_socket = server_socket
        self._stat_callback = stat_callback

    def add_to_loop(self, loop):
        if self._eventloop:
            raise Exception('already add to loop')
        if self._closed:
            raise Exception('already closed')
        self._eventloop = loop
        self._eventloop.add(self._server_socket,
                            eventloop.POLL_IN | eventloop.POLL_ERR, self)
        self._eventloop.add_periodic(self.handle_periodic)

    def remove_handler(self, handler):
        index = self._handler_to_timeouts.get(hash(handler), -1)
        if index >= 0:
            # delete is O(n), so we just set it to None
            self._timeouts[index] = None
            del self._handler_to_timeouts[hash(handler)]

    def update_activity(self, handler, data_len):
        if data_len and self._stat_callback:
            self._stat_callback(self._listen_port, data_len)
        # set handler to active
        now = int(time.time())
        if now - handler.last_activity < eventloop.TIMEOUT_PRECISION:
            # thus we can lower timeout modification frequency
            return
        handler.last_activity = now
        index = self._handler_to_timeouts.get(hash(handler), -1)
        if index >= 0:
            self._timeouts[index] = None
        length = len(self._timeouts)
        self._timeouts.append(handler)
        self._handler_to_timeouts[hash(handler)] = length

    def _sweep_timeout(self):
        # tornado's timeout memory management is more flexible than we need
        # we just need a sorted last_activity queue and it's faster than heapq
        # in fact we can do O(1) insertion/remove so we invent our own
        if self._timeouts:
            logging.log(utils.VERBOSE_LEVEL, 'sweeping timeouts')
            now = time.time()
            length = len(self._timeouts)
            pos = self._timeout_offset
            while pos < length:
                handler = self._timeouts[pos]
                if handler:
                    if now - handler.last_activity < self._timeouts:
                        break
                    else:
                        if handler.remote_address:
                            logging.warn('timed out: %s:%d' %
                                         handler.remote_address)
                        else:
                            logging.warn('timed out')
                        handler.destroy()
                        self._timeouts[pos] = None  # free memory
                        pos += 1
                else:
                    pos += 1
            if pos > TIMEOUTS_CLEAN_SIZE and pos > length >> 1:
                # clean up the timeout queue when it gets larger than half
                # of the queue
                self._timeouts = self._timeouts[pos:]
                for key in self._handler_to_timeouts:
                    self._handler_to_timeouts[key] -= pos
                pos = 0
            self._timeout_offset = pos

    def handle_event(self, sock, fd, event):
        # handle events and dispatch to handlers
        if sock:
            logging.log(utils.VERBOSE_LEVEL, 'fd %d %s', fd,
                        eventloop.EVENT_NAMES.get(event, event))
        if sock == self._server_socket:
            if event & eventloop.POLL_ERR:
                raise Exception('serever_socket error')
            try:
                logging.debug('accept')
                conn = self._server_socket.accept()
                TCPRelayHandler(self, self._fd_to_handlers,
                                self._eventloop, conn[0], self._config,
                                self._dns_resolver, self._is_local)

            except (OSError, IOError) as e:
                error_no = eventloop.errno_from_exception(e)
                if error_no in (errno.EAGAIN, errno.EINPROGRESS,
                                errno.EWOULDBLOCK):
                    return
                else:
                    utils.print_exception(e)
                    if self._config['verbose']:
                        traceback.print_exc()
        else:
            if sock:
                handler = self._fd_to_handlers.get(fd, None)
                if handler:
                    handler.handle_event(sock, event)
            else:
                logging.warn('poll removed fd')

    def handle_periodic(self):
        if self._closed:
            if self._server_socket:
                self._eventloop.remove(self._server_socket)
                self._server_socket.close()
                self._server_socket = None
                logging.info('closed TCP port %d', self._listen_port)
            if not self._fd_to_handlers:
                logging.info('stopping')
                self._eventloop.stop()
        self._sweep_timeout()

    def close(self, next_tick=False):
        logging.debug('TCP close')
        self._closed = True
        if not next_tick:
            if self._eventloop:
                self._eventloop.remove_periodic(self.handle_periodic)
                self._eventloop.remove(self._server_socket)
            self._server_socket.close()
            for handler in list(self._fd_to_handlers.values()):
                handler.destroy()
