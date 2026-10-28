#!/usr/bin/env python3
"""
端到端 patch 验证。

问题背景: 真实详情接口需要 x-sign/x-timestamp 签名头, 本机无法伪造,
所以之前只能验证 "点路径写入" 的单元逻辑, 无法验证
"代理真的收到上游 JSON -> 改写 -> 正确重写 Content-Length -> 返回给客户端"
这条完整链路。

本脚本用一个**本地模拟上游** (返回与真实接口同结构的 JSON, 可选 gzip)
替代真实服务器, 通过规则里的 upstream_ip/upstream_port/upstream_scheme
让代理回源到它, 从而端到端验证:
  1. 代理确实回源并拿到 JSON
  2. 四个字段确实被改写
  3. Content-Length 被正确重写 (与实际 body 长度一致)
  4. Content-Encoding / Transfer-Encoding 被正确清除
  5. gzip 压缩的上游响应也能正确解压 -> 改写 -> 重写
"""
import gzip
import json
import os
import socket
import ssl
import subprocess
import sys
import threading
import time

BASE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(BASE)


def P(rel):
    return os.path.join(ROOT, rel)


FAKE_DETAIL = {
    "code": 0,
    "message": "success",
    "success": True,
    "data": {
        "appResourceUri": "https://prod-dp-public-es33.oss-cn-shanghai.aliyuncs.com/ecology/0123456789abcdef0123456789abcdef.1",
        "appPackage": "com.icoolme.car.weather",
        "appName": "最美天气",
        "appActualSize": "7524",
        "appDisplaySize": "7M",
        "appIcon": "https://example.com/icon.png",
        "appVersion": "1.0.0",
    },
}

MOCK_PORT = 15301
PROXY_PORT = 15302


def start_mock_upstream(use_gzip):
    """模拟上游: 返回与真实接口同结构的 JSON。"""
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", MOCK_PORT))
    srv.listen(8)

    def handle(conn):
        try:
            conn.settimeout(10)
            data = b""
            while b"\r\n\r\n" not in data:
                c = conn.recv(4096)
                if not c:
                    return
                data += c
            body = json.dumps(FAKE_DETAIL, ensure_ascii=False).encode("utf-8")
            hdr = ["HTTP/1.1 200 OK",
                   "Content-Type: application/json;charset=UTF-8"]
            if use_gzip:
                body = gzip.compress(body)
                hdr.append("Content-Encoding: gzip")
            hdr.append("Content-Length: %d" % len(body))
            hdr.append("Connection: keep-alive")   # 模拟真实上游的 keep-alive
            conn.sendall(("\r\n".join(hdr) + "\r\n\r\n").encode() + body)
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def run():
        try:
            while True:
                c, _ = srv.accept()
                threading.Thread(target=handle, args=(c,), daemon=True).start()
        except OSError:
            pass

    threading.Thread(target=run, daemon=True).start()
    return srv


def make_test_rules(path, use_gzip):
    rules = json.load(open(P("store_rules.json"), encoding="utf-8"))
    for r in rules.get("patch", []):
        r["upstream_ip"] = "127.0.0.1"
        r["upstream_port"] = MOCK_PORT
        r["upstream_scheme"] = "http"
    json.dump(rules, open(path, "w", encoding="utf-8"), ensure_ascii=False, indent=2)


def start_test_proxy(rules_path):
    """起一个独立端口的测试代理实例。"""
    env = dict(os.environ)
    env["PROXY_RULES"] = rules_path
    env["PROXY_PORT"] = str(PROXY_PORT)
    env["PROXY_GATEWAY"] = "127.0.0.1"
    p = subprocess.Popen(
        [sys.executable, P("proxy_server.py")],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    # 等端口就绪
    for _ in range(60):
        time.sleep(0.25)
        s = socket.socket()
        try:
            s.connect(("127.0.0.1", PROXY_PORT))
            s.close()
            return p
        except OSError:
            s.close()
    p.kill()
    raise RuntimeError("测试代理启动超时")


def client_post(host, path, body=b"{}", timeout=15):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", PROXY_PORT),
                                                timeout=timeout),
                        server_hostname=host)
    req = (f"POST {path} HTTP/1.1\r\nHost: {host}\r\n"
           f"User-Agent: okhttp/3.14.9\r\n"
           f"Content-Type: application/json; charset=utf-8\r\n"
           f"Content-Length: {len(body)}\r\nConnection: keep-alive\r\n\r\n")
    s.settimeout(timeout)
    t0 = time.time()
    s.sendall(req.encode() + body)
    buf = b""
    try:
        while True:
            c = s.recv(65536)
            if not c:
                break
            buf += c
            he = buf.find(b"\r\n\r\n")
            if he >= 0:
                h = buf[:he].decode("latin-1", "replace").lower()
                cl = None
                for l in h.split("\r\n"):
                    if l.startswith("content-length:"):
                        cl = int(l.split(":")[1].strip())
                if cl is not None and len(buf) - (he + 4) >= cl:
                    break
    except socket.timeout:
        s.close()
        return None, {}, b"", time.time() - t0
    s.close()
    head, _, rbody = buf.partition(b"\r\n\r\n")
    hdrs = {}
    for l in head.decode("latin-1", "replace").split("\r\n")[1:]:
        if ":" in l:
            k, v = l.split(":", 1)
            hdrs[k.strip().lower()] = v.strip()
    return head.split(b"\r\n")[0].decode(), hdrs, rbody, time.time() - t0


def run_case(use_gzip, rules_path, expect_fields):
    label = "gzip 上游" if use_gzip else "明文上游"
    print(f"\n{'=' * 66}")
    print(f"[端到端 patch] {label}")
    print("=" * 66)

    mock = start_mock_upstream(use_gzip)
    make_test_rules(rules_path, use_gzip)
    proxy = start_test_proxy(rules_path)
    ok = True
    try:
        host = "prod-r-platform.z-onesoft.com"
        path = "/eco/ippf/appMarket/vehicle/app/detail"
        status, hdrs, body, dt = client_post(host, path)

        def chk(name, cond, detail=""):
            nonlocal ok
            ok = ok and bool(cond)
            print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
                  + (f"  ({detail})" if detail else ""))

        chk("响应状态 200", status == "HTTP/1.1 200 OK", str(status))
        chk("响应时间 < 5s (无 keep-alive 超时)", dt < 5, f"{dt:.2f}s")
        cl = hdrs.get("content-length")
        chk("Content-Length == 实际 body 长度",
            cl is not None and int(cl) == len(body), f"{cl} vs {len(body)}")
        chk("Content-Encoding 已清除", "content-encoding" not in hdrs,
            hdrs.get("content-encoding"))
        chk("Connection: close", hdrs.get("connection") == "close",
            hdrs.get("connection"))
        try:
            obj = json.loads(body.decode("utf-8"))
            chk("响应是合法 JSON", True)
        except Exception as e:
            chk("响应是合法 JSON", False, str(e))
            return ok
        for field, want in expect_fields.items():
            cur = obj
            for seg in field.split("."):
                cur = cur.get(seg) if isinstance(cur, dict) else None
            chk(f"{field} == {want!r}", cur == want, f"实际 {cur!r}")
        chk("appResourceUri 未被改动",
            obj["data"]["appResourceUri"].endswith(".1"))
    finally:
        proxy.kill()
        mock.close()
    return ok


def main():
    # 代理需要支持通过环境变量指定规则文件/端口, 先确认
    src = open(P("proxy_server.py"), encoding="utf-8").read()
    if "PROXY_RULES" not in src:
        print("需要先让 proxy_server.py 支持 PROXY_RULES/PROXY_PORT 环境变量")
        return 2

    rules_path = P("store_rules.test.json")
    expect = {
        "data.appName": "德赛西威无线ADB按钮加大版",
        "data.appPackage": "com.desay.xadb",
        "data.appActualSize": "457",
        "data.appDisplaySize": "0M",
    }
    a = run_case(False, rules_path, expect)
    b = run_case(True, rules_path, expect)
    os.remove(rules_path)

    print("\n" + "=" * 66)
    print(f"端到端 patch 验证: {'全部通过' if (a and b) else '存在失败'}")
    print("=" * 66)
    return 0 if (a and b) else 1


if __name__ == "__main__":
    sys.exit(main())
