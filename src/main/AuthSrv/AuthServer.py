# coding : utf-8


import hashlib
import threading
from time import ctime
import pymysql
from util import *
import yaml


MESSAGE_EXAMPLE = {
    "userIP": "",
    "userID": "",
    "serverIP": "",
    "serverID": "",
    "credential": "hex",
    "time": "1645527726",
    "mess_type": "cre/con/log/pol",    # 消息类型：凭证传递、内容传递、登陆消息、授权策略
    "content": ""
}

print('=========SDP权限服务器=========')
# 读取配置文件
try:
    f = open('config.yaml', 'r')
    global_config = yaml.load(f.read(), Loader=yaml.FullLoader)
    is_debug_mode = global_config['isDebugMode']
    # {'AuthServer': {'port': 6789, 'id': 1, 'db_host': 'localhost', 'db_user': 'root', 'db_password': '', 'db_database': 'SDP', 'certificate_validity': 60}, 'AppServer': {'port': 6790, 'id': 1}, 'Client': {'id': 1}}
    print('==========读取配置文件=========')
    f = open('config.yaml', 'r')
    print(f.read() + '\n===============================')
    f.close()

except Exception as e:
    log(con='配置读取错误！错误信息'+str(e), type=ERROR)
    exit(1)


# 连接数据库
db_host = global_config['AuthServer']['db_host']
db_user = global_config['AuthServer']['db_user']
db_password = global_config['AuthServer']['db_password']
db_database = global_config['AuthServer']['db_database']
db = None
# 打开数据库连接
try:
    db = pymysql.connect(host=db_host, user=db_user,
                         password=db_password, database=db_database)
    print()
    log(con='数据库连接成功'+' '+db_host+' '+db_user+' '+db_database)
except Exception as e:
    log(con='数据库连接失败，错误信息：', type=ERROR)
    exit(2)  # 错误代码




# 登陆操作
def sign_in(message: dict) -> str:
    debug(is_debug_mode)
    global db

    # 分离凭证中的账号密码
    account, password = message["content"].split(":")

    # 使用 cursor() 方法创建一个游标对象 cursor
    cursor = db.cursor()

    # 使用 execute() 方法选择凭证表
    cursor.execute(f"SELECT * FROM credential WHERE account = '{account}'")

    # 获取查找到的结果
    try:
        search_accout, search_password = cursor.fetchone()
    except Exception as e:
        log(con='找不到账户: '+account, type=ERROR)
        return 'Failure'
    
    if search_accout == account and search_password == password:
        log(con='登录成功')
        return gen_cred(message)
    else:
        log(con='登陆失败：密码错误', type=ERROR)
        return 'Failure'


# 凭证生成
def gen_cred(message: dict):
    debug(is_debug_mode)
    sha256_obj = hashlib.sha256()

    sha256_obj.update(message["userIP"].encode('utf-8'))
    sha256_obj.update(str(message["userID"]).encode('utf-8'))
    # 要请求的应用服务器ip
    sha256_obj.update(global_config['AppServer']['ip'].encode('utf-8'))
    # 要请求的用户服务器id，约定在登陆时放入content中
    sha256_obj.update(str(message['serverID']).encode('utf-8'))

    # 获取凭证生成时间
    current_time = int(gTime())
    # 凭证只在时间在不大于当前时间条件下最大的能被凭证有效期整除的时间至未来有效时间内有效
    sha256_obj.update(str(current_time - (current_time % global_config['AuthServer']['certificate_validity'])).encode('utf-8'))
    
    # 加盐
    sha256_obj.update(global_config['AuthServer']['server_private_key'].encode('utf-8'))

    # 返回凭证
    return sha256_obj.hexdigest()


def cert_verify(message: dict) -> bool:
    debug(is_debug_mode)
    sha256_obj = hashlib.sha256()

    sha256_obj.update(message["userIP"].encode('utf-8'))
    sha256_obj.update(str(message["userID"]).encode('utf-8'))
    sha256_obj.update(message['serverIP'].encode('utf-8'))
    sha256_obj.update(str(message['serverID']).encode('utf-8'))

    # 获取凭证生成时间
    current_time = int(gTime())
    # 凭证只在时间在不大于当前时间条件下最大的能被凭证有效期整除的时间至未来有效时间内有效
    sha256_obj.update(str(current_time - (current_time % global_config['AuthServer']['certificate_validity'])).encode('utf-8'))

    # 加盐
    sha256_obj.update(global_config['AuthServer']['server_private_key'].encode('utf-8'))

    # 生成当前会话绑定的用户与服务端哈希
    hash_result = sha256_obj.hexdigest()
    
    # 返回验证结果
    # print(hash_result)
    # print(message['content'])
    if hash_result == message['content']:
        log(con='用户 '+message['userID']+' 凭证验证成功!')
        return True
    return False




# 处理新建的连接
def tcp_link(client_socket, ip_addr):
    debug(is_debug_mode)
    log(type=CONNECTION, add=ip_addr)

    msg = '欢迎访问SDP权限服务器！' + "\n"
    client_socket.send(msg.encode('utf-8'))

    # 循环处理客户端请求
    while True:
        # 接受来自客户端数据
        date = client_socket.recv(1024)
        if not date:
            log(type=DISCONNECT, add=ip_addr)
            break

        try:
            # 解码消息
            date_str = date.decode('utf-8').strip()
            # 打印消息
            log(type=RECEIVE, add=ip_addr, con=date_str)


            # 解析消息到字典变量
            message = json.loads(date_str)

            # 处理消息
            # 登陆消息
            if message['mess_type'] == 'log':
                # 调用登陆函数
                sign_in_result = sign_in(message)

                # 凭证错误，登陆失败
                if sign_in_result == 'Failure':
                    client_socket.send(pack_mess(uIP=message['userIP'], uID=message['userID'], sIP='', sID=message['serverID'], cre='', mess_type='cre', mess=sign_in_result))
                    break
                # 登录成功，发送生成的凭证
                else:
                    client_socket.send(pack_mess(uIP=message['userIP'], uID=message['userID'], sIP=global_config['AppServer']['ip'], sID=message['serverID'], cre='', mess_type='cre', mess=sign_in_result))
            # 凭证验证消息
            elif message['mess_type'] == 'cre':
                verify_result = cert_verify(message)
                if verify_result:
                    client_socket.send(pack_mess(uIP=message['userIP'], uID=message['userID'], sIP=message['serverIP'], sID=message['serverID'], cre='', mess_type='pol', mess='admin'))
                else:
                    client_socket.send(pack_mess(uIP=message['userIP'], uID=message['userID'], sIP=message['serverIP'], sID=message['serverID'], cre='', mess_type='cre', mess='invalid'))
                    log(type=ERROR, con='凭证无效！')
                break


        except Exception as e:
            client_socket.send(f'请求处理错误！连接断开：{ip_addr}\n'.encode('utf-8'))
            log(con=f'请求处理错误！连接断开：{ip_addr}', type=ERROR)
            break

    # 关闭套接字，释放资源
    client_socket.close()


def main():
    debug(is_debug_mode)
    global db
    ssl_socket = ssl_server(global_config['AuthServer']['ip'], global_config['AuthServer']['port'], global_config['AuthServer']['listen_num'])

    # 循环建立新的连接
    while True:
        try:
            
            # 建立客户端连接
            client_socket, ip_addr = ssl_socket.accept()

            t = threading.Thread(
                target=tcp_link, args=(client_socket, ip_addr))
            t.setDaemon = True
            t.start()

        except Exception as e:
            log(con='建立连接错误'+str(e), type=ERROR)
            break

    # 关闭连接
    ssl_socket.close()
    # # 关闭数据库
    db.close()


if __name__ == '__main__':
    main()


