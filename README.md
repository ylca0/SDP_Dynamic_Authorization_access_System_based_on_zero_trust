# 基于零信任的SDP动态授权访问系统

## SDP Dynamic Authorization access System based on zero trust

## 数据传输

每次信息发送都是以一个 json 格式的消息为单位，格式如下：  

    MESSAGE_EXAMPLE = {  
        "userIP": "",  
        "userID": "",  
        "serverIP": "",  
        "serverID": "",  
        "credential" : "hex",  
        "time": "1645527726",  
        "mess_type" : "cre/con/log/pol",    # 消息类型：凭证票据传递、内容传递、登陆消息、授权策略  
        "content": ""  
    }


## 传输协议：https

## 系统运行过程
1. authServer 管控平台上线
2. user -> authServer 登陆请求
3. authServer -> user 返回凭证
4. user -> appServer  授权票据
5. appServer -> authServer 验证票据
6. authServer -> appServer 返回授权策略
7. appServer -> user  建立连接
8. user, appServer -> authServer 动态鉴权
9. authServer 动态策略管控

![image-20220130003249307](https://tva1.sinaimg.cn/large/008i3skNgy1gyv0h1zmx0j30jk0bkdgu.jpg)

## 凭证
凭证为 hex 格式，实现算法如下:  

    sha256_obj = hashlib.sha256()  
    sha256_obj.update(message["userIP"].encode('utf-8'))  
    sha256_obj.update(message["userID"].encode('utf-8'))  
    # 要请求的应用服务器ip  
    sha256_obj.update(global_config['AppServer' + message['serverID']]['ip'].encode('utf-8'))  
    # 要请求的用户服务器id，约定在登陆时放入content中  
    sha256_obj.update(message['serverID'].encode('utf-8'))  
    
    # 获取凭证生成时间  
    current_time = int(str(time()).split('.')[0])  
    # 凭证只在时间在不大于当前时间条件下最大的能被凭证有效期整除的时间至未来有效时间内有效  
    sha256_obj.update(str(current_time - (current_time % global_config['AuthServer']['certificate_validity'])).encode('utf-8'))  
    
    # 加盐  
    sha256_obj.update(str(global_config['AuthServer']['server_private_key']).encode('utf-8'))  
    
    # 返回凭证  
    return sha256_obj.hexdigest()  

