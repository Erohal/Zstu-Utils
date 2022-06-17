import argparse
import json
from base64 import b64decode, b64encode
from datetime import datetime
from re import compile
from time import sleep

from Crypto.Cipher import DES
from Crypto.Util import Padding
from prettytable import PrettyTable
from requests import Session


class ZstuSso:
    def __init__(self, username: str, password: str) -> None:
        self.__username = username
        self.__password = password
        self.__session = Session()

    def login(self) -> Session:
        login_url = 'https://sso-443.webvpn.zstu.edu.cn/login'
        res = self.__session.get(login_url).text
        execution, croypto = self.__get_execution_and_crypto(res)
        payload = \
            {
                'username': self.__username,
                'type': 'UsernamePassword',
                '_eventId': 'submit',
                'geolocation': '',
                'execution': execution,
                'captcha_code': '',
                'croypto': croypto,
                'password': self.__encrypto_password(croypto),
            }
        res = self.__session.post(login_url, payload, allow_redirects=False)

        update_url = 'https://webvpn.zstu.edu.cn/vpn_key/update'
        self.__session.get(update_url)

        jasiglogin_url = 'https://jwglxt.webvpn.zstu.edu.cn/sso/jasiglogin'
        self.__session.get(jasiglogin_url)
        if len(res.content) != 0:
            raise RuntimeError('Failed')

    def get_session(self):
        return self.__session

    def __get_execution_and_crypto(self, data: str):
        execution_pat = compile('<p id="login-page-flowkey">(.*?)</p>')
        crypto_pat = compile('<p id="login-croypto">(.*?)</p>')
        return execution_pat.search(data).group(1), crypto_pat.search(data).group(1)

    def __encrypto_password(self, key: str) -> str:
        key = b64decode(key)
        enc = DES.new(key, DES.MODE_ECB)
        data = Padding.pad(self.__password.encode('utf-8'), 16)
        return b64encode(enc.encrypt(data))


def main():
    parser = argparse.ArgumentParser(description='浙江理工大学教务系统成绩监控')
    parser.add_argument('-u', '--username', help='SSO账号', type=str, required=True)
    parser.add_argument('-p', '--password', help='SSO密码', type=str, required=True)
    parser.add_argument('-f', '--frequency', help='查询频率，单位秒', type=int, required=False, default=5)
    args = parser.parse_args()

    t = ZstuSso(args.username, args.password)
    t.login()
    s = t.get_session()

    table = PrettyTable()
    table.field_names = ['课程', '学分', '成绩', '绩点', '更新时间']
    credit_marks = 0
    total_credit = 0
    while True:
        credit_marks = 0
        total_credit = 0
        table.clear_rows()
        r = s.get(
            'https://jwglxt.webvpn.zstu.edu.cn/jwglxt/cjcx/cjcx_cxXsgrcj.html?doType=query')
        j = json.loads(r.text)
        for item in j['items']:
            if item['ksxz'] == '补考一':
                continue
            total_credit += float(item['xf'])
            credit_marks += float(item['xf']) * float(item['jd'])
            table.add_row([item['kcmc'], item['xf'],
                          item['bfzcj'], item['jd'], item['tjsj']])
        print('\033[2J\033[0;0H')
        print(table)
        print('总学分: {:.1f}, 学分绩点和: {:.2f}, GPA: {:.2f}'.format(
            total_credit, credit_marks, credit_marks / total_credit))
        print('更新时间：' + datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        sleep(args.frequency)


if __name__ == '__main__':
    main()
