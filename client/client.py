import os
import json
import base64
import socket
import time
import requests
from util.common import (
    load_public_key,
    derive_key,
    hmac_keystream,
    xor_bytes,
    verify_signature,
    get_local_ip,
    get_mac_address,
    GetHash
)




class Client(object):

    hostname = ""
    FINGERPRINT = ""
    IP = ""
    MAC = ""
    PASSWORD = ""

    SAVE_FILE = "license.obf"
    SALT = b"TouDongXiBiSi"  # 每台机器可生成唯一 salt
    
    url = ""

    def variable_auto(self):

        try:

            self.FINGERPRINT = GetHash()# 实际应使用真实机器码
            self.MAC = get_mac_address()

            with open("config.ini", "rb") as f:
                self.url = f.read().decode()

            self.hostname = socket.gethostname()
            self.IP = get_local_ip()

            if len(self.FINGERPRINT) <= 1:
                raise Exception("variable_auto  获取机器码失败不允许登录！")

        except Exception as e:
            print("variable_auto  获取本机信息失败 Error: ", e)
            return False

        return True
        # PASSWORD = "06300806"  # 用户输入


    def activation(self,server_response_json):

        data = json.loads(server_response_json)

        license_bytes = base64.b64decode(data["license_b64"])
        signature_bytes = base64.b64decode(data["signature_b64"])

        if not os.path.exists("server_public.pem"):

            response = requests.get(self.url + "Publickey")

            if response.status_code == 200 and len(response.text) > 10:
                server_public_key = response.text

                with open("server_public.pem", "wb") as f:
                    f.write(server_public_key.encode())

            else:
                raise Exception("activation  缺少公钥！")

        # 加载服务器 public key
        with open("server_public.pem", "rb") as f:
            server_public_key = load_public_key(f.read())



        # 验证签名
        if not verify_signature(server_public_key, license_bytes, signature_bytes):
            raise Exception("activation  签名验证失败！")

        # 本机派生 key
        key = derive_key(self.FINGERPRINT, self.SALT)

        # 用 keystream 加密 license
        ks = hmac_keystream(key, len(license_bytes))
        obf = xor_bytes(license_bytes, ks)

        # 保存到本地
        with open(self.SAVE_FILE, "wb") as f:
            f.write(obf)

        print("✅ 激活成功，license 已保存！")

        return True

    def offline_unlock(self):

        try:

            if not os.path.exists(self.SAVE_FILE):
                raise Exception("offline_unlock  未进行登录！")

            with open(self.SAVE_FILE, "rb") as f:
                obf = f.read()

            # 派生 key
            key = derive_key(self.FINGERPRINT, self.SALT)
            ks = hmac_keystream(key, len(obf))

            # 解密还原
            license_bytes = xor_bytes(obf, ks)
            license_json = json.loads(license_bytes.decode())

            if int(license_json["expires"]) < time.time():
                print("凭证过期")
                self.PASSWORD = input("Password: ")
                responses = self.request_url(self.url + "/login")
                self.activation(responses)

            print("✅ 本地解锁成功！")
            print("License 内容：", license_json)

        except Exception as e:
            print("本地认证错误")
            print("offline_unlock  Error")
            return False

        return True

    def request_url(self,url: str):

        data = {

            "passwd": self.PASSWORD,
            "hostname": self.hostname,
            "FINGERPRINT": self.FINGERPRINT,
            "IP": self.IP,
            "MAC": self.MAC

        }


        try:
            post = requests.post(url, data=data)

            if post.status_code != 200:
                raise Exception()

            return post.json()

        except Exception:
            print("request_url Error")

        return False

    def first_activation(self):

        try:

            self.PASSWORD = input("Password: ")

            responses = self.request_url(self.url + "/login")

            print(responses)

            return self.activation(responses)

        except Exception:

            print("激活失败")
            print("first_activation  Error")

        return False

    def main(self):

        self.variable_auto()

        if not os.path.exists(self.SAVE_FILE):


            return self.first_activation()

        else:

            return self.offline_unlock()



Client = Client().main()