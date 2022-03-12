# coding : utf-8


import copy
import json
import socket
import ssl
from time import time


MESSAGE_EXAMPLE = {
    "userIP": "",
    "userID": "",
    "serverIP": "",
    "serverID": "",
    "credential": "hex",
    "time": "1645527726",
    "mess_type": "cre/con/log/pol",    # 消息类型：凭证票据传递、内容传递、登陆消息、授权策略
    "content": ""
}

# 获取秒级时间戳


def gTime():
    return str(time()).split('.')[0]


# 打包消息
def pack_mess(uIP: str, uID: str, sIP: str, sID: str, cre: str, mess_type: str, mess: str) -> bytes:

    message_buffer = copy.deepcopy(MESSAGE_EXAMPLE)

    message_buffer["userIP"] = uIP
    message_buffer["userID"] = uID
    message_buffer["serverIP"] = sIP
    message_buffer["serverID"] = sID

    message_buffer["credential"] = cre
    message_buffer["time"] = gTime()
    message_buffer["mess_type"] = mess_type
    message_buffer["content"] = mess

    re = json.dumps(message_buffer)

    return re.encode('utf-8')



# 获取ssl_client
def ssl_client(ip: str, port: int) -> ssl.SSLSocket:
    # 生成SSL上下文
    context = ssl._create_unverified_context()
    # 加载信任根证书
    context.load_verify_locations('ca.cer')
    # 一定要注意的是这里的server_hostname不是指服务端IP，而是指服务端证书中设置的CN
    return context.wrap_socket(socket.create_connection((ip, port)), server_hostname=ip)


# 获取ssl_server
def ssl_server(ip: str, port: int, bind_num:int) -> ssl.SSLSocket:
    # 生成SSL上下文
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # 加载服务器所用证书和私钥
    context.load_cert_chain('ca.cer', 'ca.key')

    # 监听端口
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    sock.bind((ip, port))
    sock.listen(bind_num)
    # 将socket打包成SSL socket
    return context.wrap_socket(sock, server_side=True)