# common.py
# 一些公用函数：RSA序列化/签名、KDF派生、HMAC流、XOR等
# 服务端与客户端都会引用这些函数

import uuid
import hmac
import socket
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
import subprocess
import hashlib


def get_motherboard_serial():
    result = subprocess.check_output("wmic baseboard get serialnumber", shell=True)
    return result.decode().split("\n")[1].strip()

def get_cpu_id():
    result = subprocess.check_output("wmic cpu get ProcessorId", shell=True)
    return result.decode().split("\n")[1].strip()

def get_disk_serial():
    result = subprocess.check_output("wmic diskdrive get serialnumber", shell=True)
    return result.decode().split("\n")[1].strip()

def GetHash():
    fp_source = get_motherboard_serial() + get_cpu_id() + get_disk_serial()
    fingerprint = hashlib.sha256(fp_source.encode()).hexdigest()
    return fingerprint


def load_public_key(data: bytes):
    """从 PEM bytes 加载公钥"""
    return serialization.load_pem_public_key(data)

def verify_signature(public_key, data: bytes, signature: bytes) -> bool:
    """
    验证签名是否正确。
    返回 True/False（捕获异常以便调用方处理）
    """
    try:
        public_key.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


# -----------------------------
# KDF（从 password + fingerprint 生成 key）
# -----------------------------
def derive_key(fingerprint: str, salt: bytes, iterations=200000):
    """
    使用 PBKDF2-HMAC-SHA256 从 (password + fingerprint) 派生固定长度 key。
    - salt: 随机盐（每台机器/每次存储可不同）
    - iterations: 推荐调高以提高暴力破解成本（测试性能后调整）
    返回 32 字节 key（可用于 HMAC 或 AES）
    """
    return hashlib.pbkdf2_hmac(
        "sha256",
        fingerprint.encode(),
        salt,
        iterations,
        dklen=32
    )


# -----------------------------
# 用 HMAC 生成 keystream（伪随机流）
# -----------------------------
def hmac_keystream(key: bytes, length: int) -> bytes:
    """
    用 HMAC-SHA256(key, counter) 重复生成伪随机流，类似 CTR 模式。
    该流长度等于 length（按需扩展）。
    注意：这不是标准加密流生成器，但在轻量场景中足够用作 XOR 混淆。
    """
    stream = b""
    counter = 0
    while len(stream) < length:
        # counter 按 4 字节大端编码
        block = hmac.new(key, counter.to_bytes(4, 'big'), hashlib.sha256).digest()
        stream += block
        counter += 1
    return stream[:length]


# -----------------------------
# XOR 两个字节串（长度由短者决定）
# -----------------------------
def xor_bytes(data: bytes, key: bytes) -> bytes:
    """
    对应位置做 XOR。通常 key 与 data 长度相同（或 keystream 截取到 data 长度）。
    可逆：xor_bytes(xor_bytes(data, ks), ks) == data
    """
    return bytes(d ^ k for d, k in zip(data, key))


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        return local_ip

    except Exception:
        return None
    finally:
        s.close()



def get_mac_address():
    mac = uuid.getnode()
    return ':'.join(['{:02x}'.format((mac >> ele) & 0xff)
                     for ele in range(40, -1, -8)])

