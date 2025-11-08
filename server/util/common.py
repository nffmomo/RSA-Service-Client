# common.py
# 一些公用函数：RSA序列化/签名、KDF派生、HMAC流、XOR等
# 服务端与客户端都会引用这些函数

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


# -----------------------------
# RSA 生成 / 序列化 / 加载
# -----------------------------
def generate_rsa_keypair():
    """
    生成 RSA 私/公钥对（用于 server 签名与验证）。
    注意：生产环境私钥需持久化并妥善保管（不要裸放在代码库）
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_private_key(private_key):
    """把私钥序列化为 PEM bytes（未加密）"""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )


def serialize_public_key(public_key):
    """把公钥序列化为 PEM bytes"""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

# -----------------------------
# 生成签名 / 验证签名
# -----------------------------
def sign_data(private_key, data: bytes) -> bytes:
    """
    用私钥对数据签名（返回签名 bytes）。
    这里示例使用 PKCS1v15 + SHA256（简单直接），
    生产可改用 PSS（更安全）或 ECC 签名。
    """
    return private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

