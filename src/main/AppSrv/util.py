# coding : utf-8


import copy
import json
import socket
import ssl
from time import localtime, strftime, time
import traceback
      

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

CONNECTION = 0
DISCONNECT = 1
CONTENT = 2
ERROR = 3
SEND = 4
RECEIVE = 5

# 获取秒级时间戳
def gTime():
    return str(time()).split('.')[0]


def gFTime(t:int=None):
    if t == None:
        t = int(gTime())
    return strftime("%Y年%m月%d日 %H:%M:%S", localtime(t))

def log(add='NO ADDR', con:str = '', type = CONTENT):
    # 精简日志
    # if len(con) >= 40:
    #     con = con[:40] + '... ...'
    
    if type == CONNECTION:
        print('\033[32m[%s]新的连接:\033[0m%s' % (gFTime(), str(add)))
    elif type == DISCONNECT:
        print('\033[33m[%s]连接断开:\033[0m%s' % (gFTime(), str(add)))
    elif type == ERROR:
        print('\033[31m[%s]错误信息:\033[0m%s' % (gFTime(), con))
    elif type == SEND:
        print('\033[35m[%s]发送信息:\033[0m%s' % (gFTime(), con))
    elif type == RECEIVE:
        print('\033[35m[%s]接受%s的信息:\033[0m%s' % (gFTime(), str(add), con))
    else:
        print('\033[36m[%s]服务记录:\033[0m%s' % (gFTime(), con))



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


def debug(is_debug_mode):
    if is_debug_mode == True:
        input('\033[32m[DEBUG MODE] Interruption in\033[0m \033[31m' + traceback.extract_stack()[-2][2] + '()\033[0m \033[32mEnter to continue\033[0m')
    