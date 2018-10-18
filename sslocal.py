#!/bin/env python3

import asyncio
from tcprelay import LocalTCP
from crawler import get_servers
from logger import log

async def main():
    loop = asyncio.get_running_loop()
    rservers = await get_servers()
    local = lambda: LocalTCP(rservers)
    socks_server = await loop.create_server(local, 'localhost', 8080)
    log.info('sslocal start at port 8080.')
    async with socks_server:
        await socks_server.serve_forever()

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info('sslocal exit.')

