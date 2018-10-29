import socket
import struct
import asyncio
import random
from enum import Enum
from constants import Status, SocksAtype, SocksCmd, SocksMethod, SocksRep, SOCKS_VER
from crypto import get_cipher
from logger import log

class LocalTCP(asyncio.Protocol):
    def __init__(self, rservers):
        self._rservers = rservers

    def connection_made(self, transport):
        self._transport = transport
        self._handler = TCPHandler(transport, self._rservers)

    def data_received(self, data):
        self._handler.handle(data)

class RemoteTcp(asyncio.Protocol):
    def __init__(self, ltransport, cipher):
        self._cipher = cipher
        self._ltransport = ltransport

    def data_received(self, data):
        if self._ltransport:
            data = self._cipher.decrypt(data)
            self._ltransport.write(data)

class TCPHandler(object):
    def __init__(self, transport, rservers):
        self._transport = transport
        self._rtransport = None
        self._cipher = None
        self._status = Status.negotiate
        self._rservers = rservers


    def handle(self, data):
        if self._status == Status.negotiate:
            asyncio.create_task(self._negotiate(data))
        elif self._status == Status.request:
            asyncio.create_task(self._request(data))
        elif self._status == Status.stream:
            asyncio.create_task(self._stream(data))
        else:
            self.close()

    def close(self):
        self._status = Status.error
        self._transport.close()
        if self._rtransport:
            self._transport.close()

    async def _open_rserver(self):
        loop = asyncio.get_running_loop()
        server = random.choice(self._rservers)
        method = server.method.lower()
        passwd = server.passwd
        dcipher = get_cipher(method, passwd)
        remote = lambda: RemoteTcp(self._transport, dcipher)
        try:
            rtransport, _ = await loop.create_connection(remote, server.addr, server.port)
        except OSError:
            log.info(f'Remote connection {server.addr}:{server.port} failed.')
            self.close()
        else:
            ecipher = get_cipher(method, passwd)
            return rtransport, ecipher


    async def _negotiate(self, data):
        """
        client => server: | VER | NMETHODS | METHODS |
        server => client: | VER | METHOD |
        """
        if data[0] != SOCKS_VER or data[1] != len(data[2:]):
            self.close()
        else:
            resp = struct.pack('!BB', SOCKS_VER, SocksMethod.no_auth.value)
            self._transport.write(resp)
            self._status = Status.request

    async def _request(self, data):
        """
        client => server: | VER | CMD | RSV | ATYPE | DST.ADDR | DST.PORT |
        server => client: | VER | REP | RSV | ATYPE | BND.ADDR | BND.PORT |
        """
        cmd= data[1]
        addr = self._resolve_addr(data)
        if cmd != SocksCmd.connect.value or not addr:
            self.close()
        else:
            if not self._rtransport:
                self._rtransport, self._cipher = await self._open_rserver()
            self._rtransport.write(self._cipher.encrypt(data[3:]))
            self._status = Status.stream
            rep = SocksRep.succeeded.value
            resp = struct.pack('!4BIH', SOCKS_VER, rep, 0, 1, 0, 0)
            self._transport.write(resp)


    async def _stream(self, data):
        if self._rtransport:
            data = self._cipher.encrypt(data)
            self._rtransport.write(data)

    def _resolve_addr(self, data):
        atype = data[3]
        if atype == SocksAtype.ipv4.value:
            host = socket.inet_ntoa(data[4:8])
            port = int.from_bytes(data[8:10], 'big')
        elif atype == SocksAtype.domain.value:
            dlen = data[4]
            host = data[5:5+dlen].decode()
            port = int.from_bytes(data[5+dlen:7+dlen], 'big')
        elif atype == SocksAtype.ipv6.value:
            host = socket.inet_ntop(socket.AF_INET6, data[4:20])
            port = int.from_bytes(data[20:22], 'big')
        else:
            return None
        return (host, port)