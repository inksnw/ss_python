#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import logging
import json
import traceback
from common import to_bytes, to_str
verbose = 0
VERBOSE_LEVEL = 5


def print_exception(e):
    global verbose
    logging.error(e)
    if verbose > 0:
        import traceback
        traceback.print_exc()


def find_config():
    config_path = 'config.json'
    if os.path.exists(config_path):
        return config_path
    config_path = os.path.join(os.path.dirname(__file__), '../', 'config.json')
    if os.path.exists(config_path):
        return config_path
    return None


def get_config():
    global verbose

    logging.basicConfig(level=logging.INFO, format='%(levelname)-s: %(message)s')

    config_path = find_config()
    if config_path:
        logging.info('loading config from %s' % config_path)
        with open(config_path, 'rb') as f:
            config = json.loads(f.read().decode('utf8'))
    else:
        logging.error('config not specified')
        sys.exit(2)

    config['password'] = to_bytes(config.get('password', b''))
    config['method'] = to_str(config.get('method', 'aes-256-cfb'))
    config['port_password'] = config.get('port_password', None)
    config['timeout'] = int(config.get('timeout', 300))
    config['fast_open'] = config.get('fast_open', False)
    config['workers'] = config.get('workers', 1)
    config['pid-file'] = config.get('pid-file', '/var/run/shadowsocks.pid')
    config['log-file'] = config.get('log-file', '/var/log/shadowsocks.log')
    config['verbose'] = config.get('verbose', False)
    config['local_address'] = to_str(config.get('local_address', '127.0.0.1'))
    config['local_port'] = config.get('local_port', 1080)
    config['one_time_auth'] = config.get('one_time_auth', False)
    config['prefer_ipv6'] = config.get('prefer_ipv6', False)
    config['server_port'] = config.get('server_port', 8388)
    config['dns_server'] = config.get('dns_server', None)
    config['libopenssl'] = config.get('libopenssl', None)
    config['libmbedtls'] = config.get('libmbedtls', None)
    config['libsodium'] = config.get('libsodium', None)

    config['tunnel_remote'] = to_str(config.get('tunnel_remote', '8.8.8.8'))
    config['tunnel_remote_port'] = config.get('tunnel_remote_port', 53)
    config['tunnel_port'] = config.get('tunnel_port', 53)
    config['crypto_path'] = {'openssl': config['libopenssl'],
                             'mbedtls': config['libmbedtls'],
                             'sodium': config['libsodium']}

    logging.getLogger('').handlers = []
    logging.addLevelName(VERBOSE_LEVEL, 'VERBOSE')
    if config['verbose'] >= 2:
        level = VERBOSE_LEVEL
    elif config['verbose'] == 1:
        level = logging.DEBUG
    elif config['verbose'] == -1:
        level = logging.WARN
    elif config['verbose'] <= -2:
        level = logging.ERROR
    else:
        level = logging.INFO
    verbose = config['verbose']
    logging.basicConfig(level=level,
                        format='%(asctime)s %(filename)s %(lineno)-4s %(levelname)-6s %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S')

    return config
