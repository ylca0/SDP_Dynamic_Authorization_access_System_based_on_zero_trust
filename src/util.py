# coding : utf-8


import copy
import json
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
def pack_mess(uIP:str, uID:str, sIP:str, sID:str, cre:str, mess_type:str, mess:str) -> bytes:

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


