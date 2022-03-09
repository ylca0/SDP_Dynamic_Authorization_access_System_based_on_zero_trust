# coding : utf-8


import hashlib
import socket
import threading
from time import ctime
from httpx import Auth
import pymysql
from rsa import verify
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
    # {'AuthServer': {'port': 6789, 'id': 1, 'db_host': 'localhost', 'db_user': 'root', 'db_password': '', 'db_database': 'SDP', 'certificate_validity': 60}, 'AppServer': {'port': 6790, 'id': 1}, 'Client': {'id': 1}}
    print('==========读取配置文件=========')
    f = open('config.yaml', 'r')
    print(f.read() + '\n===============================')
    f.close()

except Exception as e:
    print('配置读取错误！错误信息：')
    print(e)
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
    print('数据库连接成功', db_host, db_user, db_database)
except Exception as e:
    print('数据库连接失败，错误信息：')
    print(e)
    exit(2)  # 错误代码




# 登陆操作
def sign_in(message: dict) -> str:
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
        print('找不到账户:', account)
        return 'Failure'

    if search_accout == account and search_password == password:
        print('登录成功')
        return gen_cred(message)
    else:
        print('登陆失败：密码错误')
        return 'Failure'


# 凭证生成
def gen_cred(message: dict):
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
    if hash_result == message['content']:
        print('success!')
        return True
    return False




# 处理新建的连接
def tcp_link(client_socket, ip_addr):
    print("新的tcp_link：%s" % str(ip_addr))

    msg = '欢迎访问SDP权限服务器！' + "\r\n"
    client_socket.send(msg.encode('utf-8'))

    # 循环处理客户端请求
    while True:
        # 接受来自客户端数据
        date = client_socket.recv(1024)
        if not date:
            print('[%s] 连接断开:%s ' % (ctime(), str(ip_addr)))
            break

        try:
            # 解码消息
            date_str = date.decode('utf-8').strip()
            # 打印消息
            print(f'[{ctime()}] 来自 {ip_addr} 的消息: {date_str}')


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
                    client_socket.send(pack_mess(uIP=message['userIP'], uID=message['userID'], sIP=message['serverIP'], sID=message['serverID'], cre='', mess_type='cre', mess='admin'))
                else:
                    client_socket.send(pack_mess(uIP=message['userIP'], uID=message['userID'], sIP=message['serverIP'], sID=message['serverID'], cre='', mess_type='cre', mess='invalid'))
                    print('凭证无效！')
                break


        except Exception as e:
            client_socket.send(f'请求处理错误！连接断开：{ip_addr}\n'.encode('utf-8'))
            print(f'请求处理错误！连接断开：{ip_addr}')
            print(e)
            break

    # 关闭套接字，释放资源
    client_socket.close()


def main():
    global db
    # 创建 socket 对象
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # 设置通讯端口
    port = global_config['AuthServer']['port']

    # 监听
    server_socket.bind(("0.0.0.0", port))

    # 设置最大连接数，超过后排队
    server_socket.listen(5)

    # 循环建立新的连接
    while True:
        try:
            # 建立客户端连接
            client_socket, ip_addr = server_socket.accept()

            t = threading.Thread(
                target=tcp_link, args=(client_socket, ip_addr))
            t.setDaemon(True)
            t.start()

        except Exception as e:
            print(e)
            break

    # 关闭连接
    server_socket.close()
    # 关闭数据库
    db.close()


if __name__ == '__main__':
    main()


