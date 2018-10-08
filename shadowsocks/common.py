#!/usr/bin/env python
# -*- coding: utf-8 -*-
import struct

ADDRTYPE_IPV4 = 0x01
ADDRTYPE_IPV6 = 0x04
ADDRTYPE_HOST = 0x03
ADDRTYPE_AUTH = 0x10
ADDRTYPE_MASK = 0xF

ONETIMEAUTH_BYTES = 10
ONETIMEAUTH_CHUNK_BYTES = 12
ONETIMEAUTH_CHUNK_DATA_LEN = 2


def onetimeauth_verify(_hash, data, key):
    return _hash == sha1_hmac(key, data)[:ONETIMEAUTH_BYTES]


def onetimeauth_gen(data, key):
    return sha1_hmac(key, data)[:ONETIMEAUTH_BYTES]


def to_bytes(s):
    if bytes != str:
        if type(s) == str:
            return s.encode('utf-8')
    return s


def to_str(s):
    if bytes != str:
        if type(s) == bytes:
            return s.decode('utf-8')
    return s


def compat_ord(s):
    if type(s) == int:
        return s
    return _ord(s)


def compat_chr(d):
    if bytes == str:
        return _chr(d)
    return bytes([d])


_ord = ord
_chr = chr
ord = compat_ord
chr = compat_chr


# add ss header
def add_header(address, port, data=b''):
    _data = b''
    _data = pack_addr(address) + struct.pack('>H', port) + data
    return _data


def parse_header(data):
    addrtype = ord(data[0])
    dest_addr = None
    dest_port = None
    header_length = 0
    if addrtype & ADDRTYPE_MASK == ADDRTYPE_IPV4:
        if len(data) >= 7:
            dest_addr = socket.inet_ntoa(data[1:5])
            dest_port = struct.unpack('>H', data[5:7])[0]
            header_length = 7
        else:
            logging.warn('header is too short')
    elif addrtype & ADDRTYPE_MASK == ADDRTYPE_HOST:
        if len(data) > 2:
            addrlen = ord(data[1])
            if len(data) >= 4 + addrlen:
                dest_addr = data[2:2 + addrlen]
                dest_port = struct.unpack('>H', data[2 + addrlen:4 +
                                                     addrlen])[0]
                header_length = 4 + addrlen
            else:
                logging.warn('header is too short')
        else:
            logging.warn('header is too short')
    elif addrtype & ADDRTYPE_MASK == ADDRTYPE_IPV6:
        if len(data) >= 19:
            dest_addr = socket.inet_ntop(socket.AF_INET6, data[1:17])
            dest_port = struct.unpack('>H', data[17:19])[0]
            header_length = 19
        else:
            logging.warn('header is too short')
    else:
        logging.warn('unsupported addrtype %d, maybe wrong password or '
                     'encryption method' % addrtype)
    if dest_addr is None:
        return None
    return addrtype, to_bytes(dest_addr), dest_port, header_length
