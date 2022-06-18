import socket
import struct
import sys
import time
import dns.resolver

from utils import wait_for, checksum
from messages import prepareVersionMessage, unpackVersionMessage, unpackAddrMessage, preparePayload

DEFAULT_PORT = 22556

# Get DNS see ip
DNS_SERVERS = ["seed.multidoge.org", "seed2.multidoge.org"]
ips = []

for dns_seed in DNS_SERVERS:
    result = dns.resolver.query(dns_seed, 'A')
    for ipval in result:
        addr = ipval.to_text()
        ips.append((addr, DEFAULT_PORT))

print("Number of ips : {}".format(len(ips)))

for host in ips:
    print("Attempt to connect to node {}".format(host[0]))

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect(host)
    except:
        print("Fail to connect")
        continue

    # Prepare Version Message
    version_message = prepareVersionMessage(host[0], host[1])
    payload = preparePayload(version_message, b'version')
    # Send Version Message
    s.send(payload)

    # Received Version Message
    version = wait_for(s, b'version')
    magic, command, m_length, chcksm = struct.unpack('4s12sI4s', version[0:24])
    if b'version' not in command:
        print("ERROR : wrong command")
        sys.exit()

    version = unpackVersionMessage(version[24:])
    print("User Agent : {}".format(version[3].decode("utf-8")))

    payload = preparePayload(b'', b'verack')
    s.send(payload)
    wait_for(s, b'verack')

    try:
        payload = preparePayload(b'', b'getaddr')
        s.send(payload)
        data = wait_for(s, b'addr')
    except:
        print("Fail to get peer addresses")
        continue
    addresses = unpackAddrMessage(data[24:])
    for addr in addresses:
        if not addr in ips:
            ips.append(addr)

    s.close()

print(ips)
print("Number of ips : {}".format(len(ips)))