# coding : utf-8


import socket
from time import ctime, sleep
from util import *
import yaml
import requests



print('===========SDP客户端===========')
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


# 获取本地用户一些信息
local_public_ip = requests.get('https://checkip.amazonaws.com').text.strip()
print('本地公网IP地址:', local_public_ip)

# 输入登陆账号密码
user_accout = None
user_password = None



def sign_in():
    
    # 连接权限服务器
    while True:
        try:
            authServer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            authServer.connect((global_config['AuthServer']['ip'], int(global_config['AuthServer']['port'])))
            print('权限服务器连接成功')
            print(f'[{ctime()}] 来自 ' + global_config['AuthServer']['ip'] + ' 的消息: ' + authServer.recv(1024).decode('utf-8'))
            break
        except Exception as e:
            print(f'[{ctime()}] 连接权限服务器失败，五秒后重试...')
            authServer.close()
            sleep(5)
            continue

    
    # 接收服务器消息
    while True:
        try:
            # 发送用户登陆消息
            authServer.send(pack_mess(uIP=local_public_ip, uID=user_accout, sIP=global_config['AppServer']['ip'], sID=global_config['AppServer']['id'], cre='', mess_type='log', mess=f'{user_accout}:{user_password}'))

            # 服务器返回消息
            date = authServer.recv(1024)
            # 检查是否断开
            if not date:
                print('[%s] 失去权限服务器的连接:%s ' % (ctime(), global_config['AuthServer']['ip']))
                break
            
            # 解码消息
            date_str = date.decode('utf-8').strip()
            # 打印消息
            print(f'[{ctime()}] 来自 ' + global_config['AuthServer']['ip'] + ' 的消息: ' + date_str)
            # 解析消息
            server_result = json.loads(date_str)

            # 如果登陆成功
            if server_result['content'] != 'Failure':
                authServer.close()
                # 关闭连接，返回凭证
                return server_result
            
            return 'Failure'

        except Exception as e:
            print('会话出错:')
            print(e)
            break
    
    authServer.close()
    return 'Failure'



# 与应用服务器敲门授权票据
def access_application(credential: str):
    # 连接应用服务器
    while True:
        try:
            appServer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            appServer.connect((global_config['AppServer']['ip'], int(global_config['AppServer']['port'])))
            print('应用服务器连接成功')
            print(f'[{ctime()}] 来自 ' + global_config['AppServer']['ip'] + ' 的消息: ' + appServer.recv(1024).decode('utf-8'))
            break
        except Exception as e:
            print(f'[{ctime()}] 连接应用服务器失败，五秒后重试...')
            appServer.close()
            sleep(5)
            continue

    
    # 接收服务器消息
    while True:
        try:
            # 发送应用验证消息
            appServer.send(pack_mess(uIP=local_public_ip, uID=user_accout, sIP=global_config['AppServer']['ip'], sID=global_config['AppServer']['id'], cre='', mess_type='cre', mess=f'{credential}'))

            # 服务器返回消息
            date = appServer.recv(1024)
            # 检查是否断开
            if not date:
                print('[%s] 失去应用服务器的连接:%s ' % (ctime(), global_config['AuthServer']['ip']))
                break
            
            # 解码消息
            date_str = date.decode('utf-8').strip()
            # 打印消息
            print(f'[{ctime()}] 来自 ' + global_config['AppServer']['ip'] + ' 的消息: ' + date_str)
            # 解析消息
            validation_result = json.loads(date_str)

            # 如果验证敲门成功
            if validation_result['content'] != 'invalid':
                appServer.close()
                # 关闭连接，返回结果
                return validation_result
            
            return 'invalid'

        except Exception as e:
            print('会话出错:')
            print(e)
            break
    
    appServer.close()
    return 'invalid'




def main():
    global user_accout, user_password

    while True:
        # 输入账户信息
        user_accout = input('请输入用户账号:\n')
        user_password = input('请输入用户密码:\n')


        sign_in_result = sign_in()
        if sign_in_result != 'Failure':
            print('登陆成功')
            validation_result = access_application(sign_in_result['content'])
            if validation_result != 'invalid':
                print('成功访问应用服务器！')

                print(validation_result)
            break
        else:
            print('登陆失败，请重试')


    return 0





if __name__ == '__main__':
    main()
