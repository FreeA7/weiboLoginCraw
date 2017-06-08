# Script Name   : jwc_craw.py
# Author        : FreeA7 陈晟昊
# Company       : ZMData
# Python Version: 3.5.2 64 bit (AMD64)


import base64
import requests
import time
import json
import re
import rsa
import binascii


# 确认登录信息与登录时要模仿的浏览器的headers
def getInfo():
    user = '用户名'
    pwd = '密码'
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36',
               'host': 'weibo.com',
               'referer': 'http://weibo.com/',
               'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
               'accept_encoding': 'gzip, deflate',
               'accept_language': 'zh-CN,zh;q=0.8'}
    return user, pwd, headers


# 使用base64加密方式加密用户名
def encrypUsername(user):
    after_encry_user = base64.b64encode(user.encode('utf-8')).decode('utf-8')
    return after_encry_user


# 使用加密后的密码向服务器请求加密密码的参数
def getPwdEncryParams(su, s):
    payload = {'entry': 'weibo',
               'callback': 'sinaSSOController.preloginCallBack',
               'rsakt': 'mod',
               'checkpin': '1',
               'client': 'ssologin.js(v1.4.18)',
               'su': su,
               '_': int(time.time() * 1000)}
    r = s.get('http://login.sina.com.cn/sso/prelogin.php', params=payload)
    json_data = json.loads(re.search('\((?P<data>.*)\)', r.text).group('data'))
    return json_data


# 使用rsa加密方式加密密码
def encryPwd(pwd, json_data):
    strpwd = (str(json_data['servertime']) + '\t' +
              str(json_data['nonce']) + '\n' + str(pwd)).encode('utf-8')
    public_key = rsa.PublicKey(int(json_data['pubkey'], 16), int('10001', 16))
    password = rsa.encrypt(strpwd, public_key)
    password = binascii.b2a_hex(password).decode()
    return password


# 登录账户
def login(su, json_data, password, s):
    data = {
        'entry': 'weibo',
        'gateway': '1',
        'from': '',
        'savestate': '7',
        'userticket': '1',
        'vsnf': '1',
        'service': 'miniblog',
        'encoding': 'UTF-8',
        'pwencode': 'rsa2',
        'sr': '1280*800',
        'prelt': '529',
        'url': 'http://weibo.com/ajaxlogin.php?framelogin=1&callback=parent.sinaSSOController.feedBackUrlCallBack',
        'rsakv': json_data['rsakv'],
        'servertime': json_data['servertime'],
        'nonce': json_data['nonce'],
        'su': su,
        'sp': password,
        'returntype': 'TEXT',
    }
    login_url = 'http://login.sina.com.cn/sso/login.php?client=ssologin.js(v1.4.18)&_=%d' % int(
        time.time())
    r = s.post(login_url, data=data)
    json_data_1 = json.loads(r.text)
    # 判断是否有验证码
    if json_data_1['retcode'] == '0':
        payload1 = {
            'callback': 'sinaSSOController.callbackLoginStatus',
            'ticket': json_data_1['ticket'],
            'ssosavestate': int(time.time()),
            'client': 'ssologin.js(v1.4.18)',
            '_': int(time.time() * 1000)
        }
        # 登录成功之后会有一个跳转，完成后返回信息
        login_url_2 = 'https://passport.weibo.com/wbsso/login'
        html_data = s.get(login_url_2, params=payload1).text
        json_data_2 = json.loads(
            re.search('\((?P<result>.*)\)', html_data).group('result'))
    else:
        print('需要验证码，出现错误！')
        exit()
    return json_data_2


# 获取所有关注人的列表
def getMyFollow(json_data_me, s):
    count = 0
    users = []
    list_inter = []

    # 获取relation_myfollow的值
    r = s.get('http://weibo.com/p/100505' +
              str(json_data_me['userinfo']['uniqueid']) + '/myfollow')
    relation_myfollow = re.search(
        'Pl_Official_RelationMyfollow__[0-9]+', r.text).group()
    relation_myfollow = re.search('[0-9]+', relation_myfollow).group()

    # 获取所有关注人的信息
    while 1:
        count += 1
        url = 'http://weibo.com/p/100505' + str(json_data_me['userinfo']['uniqueid']) + '/myfollow?t=1&cfs=&Pl_Official_RelationMyfollow__' + str(
            relation_myfollow) + '_page=' + str(count) + '#Pl_Official_RelationMyfollow__' + str(relation_myfollow)
        r = s.get(url)
        users_ = re.findall(
            'nick[=].{0,15}[&]uid[=][0-9]{0,15}[&]sex[=].{1}', r.text)
        users += users_
        list_inter += re.findall('text W[_]autocut S[_]txt2[^<]+', r.text)
        if len(users_) == 0:
            print('关注信息加载完毕，共有%d个非广告关注人已加载！' % len(users))
            break
        print('第%d页关注人已被加载！' % count)
    return users, list_inter


# 将所有人的信息记录进一个文件
def recordMyFollow(users, list_inter):
    user_list = []
    for i in range(len(users)):
        user_list.append({})
        inf_list = users[i].split('&')
        user_list[i]['introduction'] = re.sub(
            '[\r\n\t]', '', list_inter[i][48:-40])
        for j in inf_list:
            inf_list_eve = j.split('=')
            user_list[i][inf_list_eve[0]] = inf_list_eve[1]

    f = open('myfollow.txt', 'w', errors='ignore')
    f.write('name\tuid\tsex\tintroduction\n')
    for i in user_list:
        f.write(i['nick'] + '\t' + i['uid'] + '\t' +
                i['sex'] + '\t' + i['introduction'] + '\n')
        f.flush()
    f.close()


def main():
    user, pwd, headers = getInfo()                      # 确认登录信息
    s = requests.Session()                              # 设定session不用手动处理cookies
    s.get('http://weibo.com/login.php')                 # 获取登录页面
    su = encrypUsername(user)                           # 加密用户名
    json_data = getPwdEncryParams(su, s)                # 根据用户名向微博请求加密密码的参数
    password = encryPwd(pwd, json_data)                 # 加密密码
    json_data_me = login(su, json_data, password, s)    # 使用加密后的密码账号进行登录
    users, list_inter = getMyFollow(json_data_me, s)    # 获取所有关注人信息
    recordMyFollow(users, list_inter)                   # 记录所有关注人信息


if __name__ == '__main__':
    main()
