from fastapi import FastAPI, Form, Request
from fastapi.templating import Jinja2Templates
from fastapi.responses import PlainTextResponse
from datetime import datetime
import csv
import os
import ServerRSA



app = FastAPI()
templates = Jinja2Templates(directory="templates")

CSV_FILE = "log.csv"
FIELDNAMES = ["time", "hostname", "FINGERPRINT", "IP", "MAC"]


# 如果 CSV 不存在，就创建并写入表头
if not os.path.exists(CSV_FILE):
    with open(CSV_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()


def get_client_ip(request: Request) -> str:
    """
    获取客户端真实 IP
    - 优先使用 X-Forwarded-For（可能有多个 IP，用第一个）
    - 否则使用 request.client.host
    """
    x_forwarded_for = request.headers.get("X-Forwarded-For")
    if x_forwarded_for:
        # 如果有多个 IP（如 "client, proxy1, proxy2"），取第一个
        ip = x_forwarded_for.split(",")[0].strip()
    else:
        ip = request.client.host
    return ip


# POST: 处理表单提交
@app.post("/login")
def login(
        passwd: str = Form(...),
        hostname: str = Form(...),
        FINGERPRINT: str = Form(...),
        IP: str = Form(...),
        MAC: str = Form(...)
):
    now = datetime.utcnow().isoformat()
    # 写入 CSV
    with open(CSV_FILE, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writerow({
            "time": now,
            "hostname": hostname,
            "FINGERPRINT": FINGERPRINT,
            "IP": IP,
            "MAC": MAC
        })


    if passwd == "06300806":
        return ServerRSA.create_license(FINGERPRINT)
    else:
        return {"status": "fail", "msg": "用户名或密码错误"}


@app.get("/Publickey", response_class=PlainTextResponse)
def ip():

    ServerRSA.create_key()

    with open("server_public.pem", "r") as f:
        return f.read()

