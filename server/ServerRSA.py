# ServerRSA.py
# 简易示例：生成 RSA 密钥，签发 license（JSON），并打包为 base64 bundle
# 真实环境中：密钥应持久化、安全保管；签发逻辑应做权限校验与审计

import os
import json
import base64
import time
from cryptography.hazmat.primitives import serialization
from util.common import (
    generate_rsa_keypair,
    serialize_private_key,
    serialize_public_key,
    sign_data
)

def create_key():

    private_exists = os.path.exists("server_private.pem")
    public_exists = os.path.exists("server_public.pem")

    if not private_exists or not public_exists:

        server_private_key, server_public_key = generate_rsa_keypair()

        with open("server_private.pem", "wb") as f:
            f.write(serialize_private_key(server_private_key))
        with open("server_public.pem", "wb") as f:
            f.write(serialize_public_key(server_public_key))

def read_private_key():
    with open("server_private.pem", "rb") as f:

        pem_bytes = f.read()

        private_key = serialization.load_pem_private_key(
            pem_bytes,
            password=None
        )

    return private_key

def read_public_key():

    with open("server_public.pem", "rb") as f:
        pem_bytes = f.read()

    public_key = serialization.load_pem_public_key(pem_bytes)
    return public_key


# -----------------------------
# 创建 license 并签名
# -----------------------------
def create_license(user_id: str):
    """
    构建 license JSON 并用 server 私钥签名。
    返回一个 JSON 字符串（包含 base64(license_payload) 与 base64(signature)）。
    该字符串即 server 要发送给客户端的 bundle。
    """

    license_data = {
        "FINGERPRINT": user_id,
        # 这里示例设置30day后过期；如果希望长期有效可设为 0 或 omit expiry
        "expires": int(time.time()) + 3600 * 24 * 30,
    }

    if len(user_id) < 64:
        return False

    # 将 license JSON 编码为 bytes
    encoded = json.dumps(license_data).encode()

    create_key()

    server_private_key = read_private_key()

    # 用 server 私钥签名 license bytes
    signature = sign_data(server_private_key, encoded)

    # 把 payload 与签名都 base64 编码并封装成 JSON 字符串返回
    package = {
        "license_b64": base64.b64encode(encoded).decode(),
        "signature_b64": base64.b64encode(signature).decode()
    }

    return json.dumps(package)
