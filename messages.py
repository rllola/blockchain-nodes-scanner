import struct
import datetime
import socket

from utils import checksum, get_compact_size

PROTOCOL_VERSION = 70004
PORT = 43110

def prepareVersionMessage(host, port):
    version_message = struct.pack('i', PROTOCOL_VERSION)
    version_message += struct.pack('Q', 4)
    version_message += struct.pack('q', int(datetime.datetime.now().timestamp()))
    version_message += struct.pack('Q', 1)
    version_message += struct.pack('>16s', b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff'+socket.inet_aton(host))
    version_message += struct.pack('>H', port)
    version_message += struct.pack('Q', 4)
    version_message += struct.pack('>16s', b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff'+socket.inet_aton("127.0.0.1"))
    version_message += struct.pack('>H', PORT)
    version_message += struct.pack('Q', 0)
    version_message += struct.pack('B', 0)
    version_message += struct.pack('i', 0)
    version_message += struct.pack('?', False)

    return version_message

def unpackVersionMessage(data):
    offset = 0
    protocol_version = struct.unpack('i', data[offset:offset+4])
    offset += 4
    services = struct.unpack('Q', data[offset:offset+8])
    offset += 8
    timestamp = struct.unpack('q', data[offset:offset+8])
    offset += 8
    addr_rcv = struct.unpack('26s', data[offset:offset+26])[0]
    offset += 26
    addr_from = struct.unpack('26s', data[offset:offset+26])[0]
    offset += 26
    nonce = struct.unpack('Q', data[offset:offset+8])
    offset += 8
    user_agent_size_data = struct.unpack('8s', data[offset:offset+8])[0]
    user_agent_size, user_agent_offset = get_compact_size(user_agent_size_data)
    offset += user_agent_offset
    user_agent = struct.unpack('{}s'.format(user_agent_size), data[offset:offset+user_agent_size])[0]
    offset += user_agent_size
    start_height = struct.unpack('i', data[offset:offset+4])
    offset += 4
    relay = struct.unpack('?', data[offset:offset+1])

    return protocol_version, services, timestamp, user_agent, start_height, relay

def unpackAddrMessage(data):
    addresses = []
    offset = 0
    count_data = struct.unpack('8s', data[offset:offset+8])[0]
    count_size, count_offset = get_compact_size(count_data)
    offset += count_offset
    for i in range(count_size):
        timestamp = struct.unpack('I', data[offset:offset+4])
        offset += 4
        service = struct.unpack('Q', data[offset:offset+8])
        offset += 8
        addr = struct.unpack('16s', data[offset:offset+16])[0]
        offset += 16
        port = struct.unpack('>H', data[offset:offset+2])[0]
        offset += 2

        addresses.append((socket.inet_ntoa(addr[12:]), port))


    return addresses

def preparePayload(message, command):
    # REGETST
    #payload = struct.pack('4s', b'\xfa\xbf\xb5\xda')
    # TESTNET
    #payload = struct.pack('4s', b'\xfc\xc1\xb7\xdc')
    # MAINNET
    payload = struct.pack('4s', b'\xc0\xc0\xc0\xc0')
    payload += struct.pack('12s', command)
    payload += struct.pack('I', len(message))
    payload += struct.pack('4s', checksum(message)[0:4])
    payload += message

    return payload