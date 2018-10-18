from enum import Enum

SOCKS_VER = 0x05

class Status(Enum):
    negotiate = 0
    request = 1
    stream = 2
    error = -1

class SocksMethod(Enum):
    no_auth = 0x00
    gssapi = 0x01
    user_passwd = 0x02
    no_acceptable_method = 0xff

class SocksCmd(Enum):
    connect = 0x01
    bind = 0x02
    udp_associate = 0x03

class SocksAtype(Enum):
    ipv4 = 0x01
    domain = 0x03
    ipv6 = 0x04

class SocksRep(Enum):
    succeeded = 0x00
    general_server_err = 0x01
    connction_not_allowed = 0x02
    network_unreachable = 0x03
    host_unreachable = 0x04
    connection_refused = 0x05
    ttl_expired = 0x06
    cmd_not_support = 0x07
    atype_not_support = 0x08
