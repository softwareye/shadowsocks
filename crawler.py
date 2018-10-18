import re
import base64
import asyncio
import aiohttp
from collections import namedtuple
from logger import log

Server = namedtuple('Server', ['addr', 'port', 'method', 'passwd'])

async def get_servers():
    doub_url = 'https://doub.io/sszhfx/'
    log.info('start crawl servers from {}'.format(doub_url))
    ss_urls = await _crawl(doub_url)
    return list(map(_decode, ss_urls))
        
def _decode(url):
    url = (url[5:] + '==').encode('utf-8')
    url = base64.b64decode(url).decode('utf-8')
    pat = re.compile('(\S+):(\S+)@(\S+):(\S+)')
    mat = pat.match(url)
    return Server(mat.group(3), int(mat.group(4)), mat.group(1), mat.group(2))


async def _crawl(url):
    pat = re.compile(r'https://\S+text=ss://[a-z0-9]+=*', re.I)
    pat_ss = re.compile(r'ss://[a-z0-9]+=*', re.I)
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as resp:
            doc = await resp.text()
    links = pat.findall(doc)
    ret = []
    for link in links:
        async with aiohttp.ClientSession() as session:
            async with session.get(link) as resp:
                doc = await resp.text() 
        ret.append(pat_ss.search(doc).group())
    return ret

