# coding : utf-8


import socket
import subprocess
import threading
from time import ctime, sleep
from util import *
import yaml


print('=========SDP应用服务器=========')
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




def appInstance(client_socket, ip_addr, userInfo:dict):
    # out_text = subprocess.check_output(['python', '/Users/ylcao/Documents/code/python/github/SDP/src/app.py'])
    # client_socket.send(pack_mess(uIP=userInfo['userIP'], uID=userInfo['userID'], sIP=userInfo['serverIP'], sID=userInfo['serverID'], cre='', mess_type='con', mess=out_text))
    
    while True:
        try:
            # 接收消息
            date = client_socket.recv(1024)
            if not date:
                print('[%s] 失去用户客户端的连接:%s ' % (ctime(), global_config['AuthServer']['ip']))
                break
            # 解码消息
            date_str = date.decode('utf-8').strip()

            # 打印消息
            print(f'[{ctime()}] 来自 ' + ip_addr[0] + ' 的消息: ' + date_str)

            # 解析消息
            message = json.loads(date_str)
            
            # 每次消息都检验凭证是否合法
            Request_result = accessRequest(message, message['credential'])
            # 凭证无效
            if Request_result == 'invalid':
                # 发送凭证无效信息
                client_socket.send(pack_mess(uIP=message['userIP'], uID=message['userID'], sIP=message['serverIP'], sID=userInfo['serverID'], cre='', mess_type='pol', mess=Request_result))
                break
            # 凭证有效
            else:
                client_socket.send(pack_mess(uIP=message['userIP'], uID=message['userID'], sIP=message['serverIP'], sID=userInfo['serverID'], cre='', mess_type='con', mess='成功访问应用'))
       
        except Exception as e:
            print('会话出错:')
            print(e)
            break
    

    client_socket.close()



def accessRequest(message: dict, current_credential:str) -> str:

    # 连接权限服务器
    while True:
        try:
            ssl_authServer = ssl_client(global_config['AuthServer']['ip'], global_config['AuthServer']['port'])
            print('权限服务器连接成功')
            # 接收消息
            ssl_authServer.recv(1024)
            break
        except Exception as e:
            print(f'[{ctime()}] 连接权限服务器失败，五秒后重试...')
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
                print('[%s] 失去权限服务器的连接:%s ' % (ctime(), global_config['AuthServer']['ip']))
                break
            # 解码消息
            date_str = date.decode('utf-8').strip()
            # 打印消息
            print(f'[{ctime()}] 来自 ' + global_config['AuthServer']['ip'] + ' 的消息: ' + date_str)
            # 解析消息
            server_result = json.loads(date_str)

            if server_result['content'] != 'invalid':
                ssl_authServer.close()
                return server_result['content']
            
            return 'invalid'

        except Exception as e:
            print('会话出错:')
            print(e)
            break
    
    ssl_authServer.close()
    return 'invalid'



# 处理新建的连接
def tcp_link(client_socket, ip_addr):
    print("新的用户资源访问连接：%s" % str(ip_addr))

    msg = '欢迎访问SDP应用服务器！' + "\r\n"
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
            if message['mess_type'] == 'cre':
                # 调用登陆函数
                Request_result = accessRequest(message, message['content'])
                # 凭证无效
                if Request_result == 'invalid':
                    # 发送凭证无效信息
                    client_socket.send(pack_mess(uIP=message['userIP'], uID=message['userID'], sIP=message['serverIP'], sID=message['serverID'], cre='', mess_type='pol', mess=Request_result))
                    break
                # 凭证有效
                else:
                    # 发送凭证权限信息
                    client_socket.send(pack_mess(uIP=message['userIP'], uID=message['userID'], sIP=message['serverIP'], sID=message['serverID'], cre='', mess_type='pol', mess=Request_result))
                    # app实例接管
                    appInstance(client_socket, ip_addr, message)
                    # 实例运行完成即断开连接
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











