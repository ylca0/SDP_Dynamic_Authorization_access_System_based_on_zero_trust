# coding : utf-8


from ssl import SSLSocket
from time import sleep
from util import *
import yaml
import requests
from PySide2.QtWidgets import QApplication, QMessageBox
from PySide2.QtUiTools import QUiLoader
from PySide2.QtCore import QFile


# 登陆UI界面类
class ClientWindow:

    def __init__(self):
        # 初始化客户端
        self.user_accout = None
        self.user_password = None

        print('===========SDP客户端===========')
        # 读取配置文件
        try:
            f = open('config.yaml', 'r')
            self.global_config = yaml.load(f.read(), Loader=yaml.FullLoader)
            self.is_debug_mode = self.global_config['isDebugMode']
            print('==========读取配置文件=========')
            f = open('config.yaml', 'r')
            print(f.read() + '\n===============================')
            f.close()

        except Exception as e:
            self.log(con='配置读取错误！错误信息：', type=ERROR)
            exit(1)


        # 获取本地用户一些信息
        # self.local_public_ip = requests.get('https://checkip.amazonaws.com').text.strip()
        self.local_public_ip = '127.0.0.1'
        self.log(con='本地公网IP地址:'+self.local_public_ip)


        # 加载登陆界面
        qFile = QFile("ui/LoginWindow.ui")
        qFile.open(QFile.ReadOnly)
        qFile.close()
        self.ui = QUiLoader().load(qFile)
        self.ui.button_login.clicked.connect(self.login)
        self.ui.show()

        # 加载浏览界面
        qFile = QFile("ui/Brower.ui")
        qFile.open(QFile.ReadOnly)
        qFile.close()
        self.ui2 = QUiLoader().load(qFile)

    def log(self, add='NO ADDR', con:str = '', type = CONTENT):
        # 精简日志
        # if len(con) >= 40:
        #     con = con[:40] + '... ...'
        
        if type == CONNECTION:
            print('\033[32m[%s]新的连接:\033[0m%s' % (gFTime(), str(add)))
        elif type == DISCONNECT:
            print('\033[33m[%s]连接断开:\033[0m%s' % (gFTime(), str(add)))
        elif type == ERROR:
            print('\033[31m[%s]错误信息:\033[0m%s' % (gFTime(), con))
            QMessageBox.about(self.ui, 'ERROR', '[%s]\n错误信息:%s' % (gFTime(), con))
            return -1
        elif type == SEND:
            print('\033[35m[%s]发送信息:\033[0m%s' % (gFTime(), con))
        elif type == RECEIVE:
            print('\033[35m[%s]接受%s的信息:\033[0m%s' % (gFTime(), str(add), con))
        else:
            print('\033[36m[%s]服务记录:\033[0m%s' % (gFTime(), con))

        return 0

    def login(self):
        if len(self.ui.text_one.toPlainText()) > 0 and len(self.ui.text_two.toPlainText()) > 0:
            self.user_accout = self.ui.text_one.toPlainText()
            self.user_password = self.ui.text_two.toPlainText()
            sign_result = self.sign_in()
            if sign_result != -1:
                QMessageBox.about(self.ui, 'login', '登陆成功')
                self.ui.setHidden(True)
                self.ui2.show()
                self.valid_application(sign_result['serverIP'], sign_result['content'])
        else:
            QMessageBox.about(self.ui, 'ERROR', '请输入账号和密码!')


    def sign_in(self):
        debug(self.is_debug_mode)

        # 连接权限服务器
        try:
            authServer = ssl_client(
                self.global_config['AuthServer']['ip'], self.global_config['AuthServer']['port'])
            self.log(con='权限服务器连接成功', type=CONNECTION,
                add=self.global_config['AuthServer']['ip'])
            self.log(add=self.global_config['AuthServer']['ip'], con=authServer.recv(
                1024).decode('utf-8'), type=RECEIVE)
        except Exception as e:
            return self.log(con='连接权限服务器失败，请稍后后重试...', type=ERROR)

        # 接收服务器消息
        while True:

            try:
                # 发送用户登陆消息
                authServer.send(pack_mess(uIP=self.local_public_ip, uID=self.user_accout, sIP='',
                                sID=self.global_config['AppServer']['id'], cre='', mess_type='log', mess=f'{self.user_accout}:{self.user_password}'))

                # 服务器返回消息
                date = authServer.recv(1024)
                # 检查是否断开
                if not date:
                    self.log(add=self.global_config['AuthServer']['ip'], type=DISCONNECT)
                    break

                # 解码消息
                date_str = date.decode('utf-8').strip()
                # 打印消息
                self.log(add=self.global_config['AuthServer']
                    ['ip'], con=date_str, type=RECEIVE)
                # 解析消息
                server_result = json.loads(date_str)

                # 如果登陆成功
                if server_result['content'] != 'Failure':
                    authServer.close()
                    # 关闭连接，返回凭证
                    return server_result

                return self.log(con='登陆失败', type=ERROR)

            except Exception as e:
                return self.log(con='会话出错', type=ERROR)

        authServer.close()
        return self.log(con='登陆失败', type=ERROR)


    def access_application(self, appserver_ip: str, ssl_appServer: SSLSocket, credential: str):
        # 最终访问应用
        debug(self.is_debug_mode)

        # 接收服务器消息
        try:
            # 发送应用访问消息
            ssl_appServer.send(pack_mess(uIP=self.local_public_ip, uID=self.user_accout, sIP=appserver_ip,
                                sID=self.global_config['AppServer']['id'], cre=credential, mess_type='con', mess=''))
            
            # 服务器返回消息
            date = ssl_appServer.recv(1024)

            # 检查是否断开
            if not date:
                self.log(add=appserver_ip, type=DISCONNECT)
                return self.log(con='连接断开，请稍后重试...', type=ERROR)

            # 解码消息
            date_str = date.decode('utf-8').strip()
            # 打印消息
            self.log(add=appserver_ip, con=date_str, type=RECEIVE)
            # 解析消息
            accesss_result = json.loads(date_str)

            # 如果验证敲门成功
            if accesss_result['content'] != 'invalid':
                self.log(con="成功访问应用服务器！")
                self.log(con=accesss_result)
                self.ui2.brower.clear()
                self.ui2.brower.append(accesss_result['content'])
                return

            # 关闭连接，返回结果
            ssl_appServer.close()
            return accesss_result

        except Exception as e:
            self.log(type=ERROR, con=e)

        ssl_appServer.close()
        return 'invalid'

    
    def valid_application(self, appserver_ip: str, credential: str):
        # 与应用服务器敲门授权票据
        debug(self.is_debug_mode)
        # 连接应用服务器
        while True:
            try:
                ssl_appServer = ssl_client(
                    appserver_ip, self.global_config['AppServer']['port'])
                self.log(con='应用服务器连接成功')
                self.log(add=appserver_ip, con=ssl_appServer.recv(
                    1024).decode('utf-8'), type=RECEIVE)
                break
            except Exception as e:
                self.log(con='连接应用服务器失败，五秒后重试...', type=ERROR)
                sleep(5)
                continue

        # 接收服务器消息
        while True:
            try:
                # 发送应用验证消息
                ssl_appServer.send(pack_mess(uIP=self.local_public_ip, uID=self.user_accout, sIP=appserver_ip,
                                    sID=self.global_config['AppServer']['id'], cre='', mess_type='cre', mess=f'{credential}'))

                # 服务器返回消息
                date = ssl_appServer.recv(1024)
                # 检查是否断开
                if not date:
                    self.log(add=self.global_config['AppServer']['ip'], type=DISCONNECT)
                    break

                # 解码消息
                date_str = date.decode('utf-8').strip()
                # 打印消息
                self.log(add=appserver_ip, con=date_str, type=RECEIVE)
                # 解析消息
                validation_result = json.loads(date_str)

                # 如果验证敲门成功
                if validation_result['content'] != 'invalid':
                    self.log(con="成功登陆应用服务器！")
                    self.log(con=validation_result)
                    self.access_application(appserver_ip, ssl_appServer, credential)

                # 关闭连接，返回结果
                ssl_appServer.close()
                return validation_result

            except Exception as e:
                self.log(type=ERROR, con=e)
                break

        ssl_appServer.close()
        return 'invalid'



def main():
    app = QApplication([])
    MainWindowObj = ClientWindow()
    app.exec_()
    return 0
if __name__ == '__main__':
    main()
