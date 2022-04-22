# coding : utf-8


import threading
from time import ctime, sleep
import yaml
from util import *
import requests


print('=========SDP应用服务器=========')
# 读取配置文件
try:
    f = open('/Users/ylcao/Documents/code/python/github/SDP/src/main/AppSrv/config.yaml', 'r')
    global_config = yaml.load(f.read(), Loader=yaml.FullLoader)
    is_debug_mode = global_config['isDebugMode']
    # {'AuthServer': {'port': 6789, 'id': 1, 'db_host': 'localhost', 'db_user': 'root', 'db_password': '', 'db_database': 'SDP', 'certificate_validity': 60}, 'AppServer': {'port': 6790, 'id': 1}, 'Client': {'id': 1}}
    print('==========读取配置文件=========')
    f = open('/Users/ylcao/Documents/code/python/github/SDP/src/main/AppSrv/config.yaml', 'r')

    print(f.read() + '\n===============================')
    f.close()

except Exception as e:
    log(con='配置读取错误！错误信息'+str(e), type=ERROR)
    exit(1)


def sendAppContent():
    response = requests.get(global_config['AppServer']['appLoc'])
    return open('/Users/ylcao/Documents/code/python/github/SDP/src/main/AppSrv/app.html', 'r').read()
    return response.text


def appInstance(client_socket, ip_addr, message:dict):
    debug(is_debug_mode)
    
    while True:
        try:
            # 每次消息都检验凭证是否合法
            Request_result = valid_request(message, message['credential'])
            # 凭证无效
            if Request_result == 'invalid':
                # 发送凭证无效信息
                client_socket.send(pack_mess(uIP=message['userIP'], uID=message['userID'], sIP=message['serverIP'], sID=message['serverID'], cre='', mess_type='pol', mess=message))
                break
            # 凭证有效
            else:
                client_socket.send(pack_mess(uIP=message['userIP'], uID=message['userID'], sIP=message['serverIP'], sID=message['serverID'], cre='', mess_type='con', mess=sendAppContent()))

        except Exception as e:
            log(con='会话出错 '+str(e), type=ERROR)
            break
    

    client_socket.close()



def valid_request(message: dict, current_credential:str) -> str:
    debug(is_debug_mode)

    # 连接权限服务器
    while True:
        try:
            ssl_authServer = ssl_client(global_config['AuthServer']['ip'], global_config['AuthServer']['port'])
            log(con='权限服务器连接成功 '+global_config['AuthServer']['ip'])
            # 接收消息
            ssl_authServer.recv(1024)
            break
        except Exception as e:
            log(con=f'连接权限服务器失败，五秒后重试...', type=ERROR)
            ssl_authServer.close()
            sleep(5)
            continue
    
    
    while True:
        try:
            
            # 发送用户凭证消息
            ssl_authServer.send(pack_mess(uIP=message['userIP'], uID=message['userID'], sIP=message['serverIP'], sID=message['serverID'], cre='', mess_type='cre', mess=current_credential))
            # 服务器返回验证消息
            date = ssl_authServer.recv(1024)
            if not date:
                log(type=DISCONNECT, add=global_config['AuthServer']['ip'])
                break
            # 解码消息
            date_str = date.decode('utf-8').strip()
            # 打印消息
            log(type=RECEIVE, add=global_config['AuthServer']['ip'], con=date_str)


            # 解析消息
            server_result = json.loads(date_str)

            if server_result['content'] != 'invalid':
                ssl_authServer.close()
                return server_result['content']
            
            return 'invalid'

        except Exception as e:
            log(con='会话出错 '+str(e), type=ERROR)
            print(e)
            break
    
    ssl_authServer.close()
    return 'invalid'



# 处理新建的连接
def tcp_link(client_socket, ip_addr):
    debug(is_debug_mode)
    log(con='新的用户资源访问连接', type=CONNECTION, add=ip_addr)

    msg = '欢迎访问SDP应用服务器！' + "\r\n"
    client_socket.send(msg.encode('utf-8'))

    # 循环处理客户端请求
    while True:
        # 接受来自客户端数据
        date = client_socket.recv(1024)
        if not date:
            log(add=ip_addr, type=DISCONNECT)
            break

        try:
            # 解码消息
            date_str = date.decode('utf-8').strip()
            # 打印消息
            log(type=RECEIVE, add=ip_addr, con=date_str)


            # 解析消息到字典变量
            message = json.loads(date_str)

            # 处理消息
            if message['mess_type'] == 'cre':
                # 调用登陆函数
                Request_result = valid_request(message, message['content'])
                # 凭证无效
                if Request_result == 'invalid':
                    # 发送凭证无效信息
                    client_socket.send(pack_mess(uIP=message['userIP'], uID=message['userID'], sIP=message['serverIP'], sID=message['serverID'], cre='', mess_type='pol', mess=Request_result))
                    break
                # 凭证有效
                else:
                    # 发送凭证权限信息
                    client_socket.send(pack_mess(uIP=message['userIP'], uID=message['userID'], sIP=message['serverIP'], sID=message['serverID'], cre='', mess_type='pol', mess=Request_result))
            elif message['mess_type'] == 'con':
                # app实例接管
                appInstance(client_socket, ip_addr, message)
                # 实例运行完成即断开连接
                break


        except Exception as e:
            client_socket.send(f'请求处理错误！连接断开：{ip_addr}\n'.encode('utf-8'))
            log(con='请求处理错误！连接断开: '+ip_addr, type=ERROR)
            break

    # 关闭套接字，释放资源
    client_socket.close()





def main():
    debug(is_debug_mode)
    global db

    ssl_socket = ssl_server(global_config['AppServer']['ip'], global_config['AppServer']['port'], global_config['AppServer']['listen_num'])

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
            print(e)
            break

    # 关闭连接
    ssl_socket.close()
    # 关闭数据库
    db.close()





if __name__ == '__main__':
    main()











