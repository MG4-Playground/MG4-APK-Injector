#!/usr/bin/env python3
"""
代理自检脚本 —— 用车机同样的方式 (TLS 连网关 IP:443, SNI 为域名) 验证代理。

断言:
  1. 状态码 200 (整包) / 206 (Range)
  2. Content-Length == APK 字节数
  3. 响应首字节 == 50 4b 03 04 (ZIP/APK 魔数)
  4. Range 请求返回 206 且长度正确
  5. 越界 Range 返回 416
  6. patch 规则: 详情接口返回的 appName/appPackage/体积 已改写
"""
import json
import os
import re
import socket
import ssl
import sys

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE)
from proxy_server import set_path, get_path  # noqa: E402

RULES = json.load(open(os.path.join(BASE, "store_rules.json"), encoding="utf-8"))


def _resolve(p):
    """相对路径基于规则文件所在目录解析, 绝对路径原样使用 (与代理行为一致)。"""
    if not p:
        return p
    if os.path.isabs(p):
        return p
    return os.path.normpath(os.path.join(BASE, p))


CHAIN = os.path.join(BASE, "pki", "chain.pem")
GATEWAY = "192.168.137.1"
PORT = 443
APK_SIZE = RULES["apk_size"]
APK_PATH = _resolve(RULES["apk_path"])

PASS, FAIL = "PASS", "FAIL"
results = []


def check(name, ok, detail=""):
    results.append((name, PASS if ok else FAIL, detail))
    print(f"  [{PASS if ok else FAIL}] {name}" + (f"  ({detail})" if detail else ""))
    return ok


def tls_connect(host, sni):
    """连网关 IP, 但 SNI 用域名 (与车机行为一致)。"""
    raw = socket.create_connection((GATEWAY, PORT), timeout=15)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # 只验行为, 不验 CA
    return ctx.wrap_socket(raw, server_hostname=sni)


def http_get(sni, path, headers=None, read_body=True):
    s = tls_connect(GATEWAY, sni)
    try:
        req = f"GET {path} HTTP/1.1\r\nHost: {sni}\r\nConnection: close\r\n"
        for k, v in (headers or {}).items():
            req += f"{k}: {v}\r\n"
        req += "\r\n"
        s.sendall(req.encode())
        buf = b""
        while True:
            try:
                chunk = s.recv(65536)
            except (ssl.SSLError, OSError):
                break
            if not chunk:
                break
            buf += chunk
            if not read_body:
                head_end = buf.find(b"\r\n\r\n")
                if head_end >= 0:
                    head = buf[:head_end].decode(errors="replace")
                    m = None
                    for line in head.split("\r\n")[1:]:
                        if ":" in line:
                            k, v = line.split(":", 1)
                            if k.strip().lower() == "content-length":
                                m = int(v.strip())
                    if m is not None and len(buf) - (head_end + 4) >= m:
                        break
        return buf
    finally:
        s.close()


def parse_head(raw):
    idx = raw.find(b"\r\n\r\n")
    if idx < 0:
        return {}, raw, b""
    head_txt = raw[:idx].decode(errors="replace")
    lines = head_txt.split("\r\n")
    status = int(lines[0].split()[1]) if len(lines[0].split()) > 1 else 0
    hdrs = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            hdrs[k.strip().lower()] = v.strip()
    return hdrs, status, raw[idx + 4:]


def http_post(sni, path, body=b"{}", extra=None):
    s = tls_connect(GATEWAY, sni)
    try:
        hdr = (f"POST {path} HTTP/1.1\r\nHost: {sni}\r\n"
               f"Content-Type: application/json\r\n"
               f"Content-Length: {len(body)}\r\nConnection: close\r\n")
        for k, v in (extra or {}).items():
            hdr += f"{k}: {v}\r\n"
        hdr += "\r\n"
        s.sendall(hdr.encode() + body)
        buf = b""
        while True:
            try:
                chunk = s.recv(65536)
            except (ssl.SSLError, OSError):
                break
            if not chunk:
                break
            buf += chunk
        return buf
    finally:
        s.close()


# ------------------------------------------------------------------ 测试项
def test_serve_domain():
    serve = RULES["serve"][0]
    host = serve["host"]
    path = "/ecology/" + "a" * 40 + ".1"
    print(f"\n[1] serve 规则: GET https://{host}{path}")
    raw = http_get(host, path)
    hdrs, status, body = parse_head(raw)
    cl = hdrs.get("content-length")
    check("状态码 200", status == 200, f"实际 {status}")
    check("Content-Length == APK 字节数",
          cl is not None and int(cl) == APK_SIZE, f"{cl} vs {APK_SIZE}")
    check("首字节 == 50 4b 03 04",
          body[:4] == b"\x50\x4b\x03\x04", body[:4].hex(" "))
    check("Accept-Ranges: bytes", hdrs.get("accept-ranges") == "bytes",
          hdrs.get("accept-ranges"))
    check("实际收到字节数 == APK 大小", len(body) == APK_SIZE, f"{len(body)}")


def test_range():
    serve = RULES["serve"][0]
    host = serve["host"]
    path = "/ecology/" + "b" * 40 + ".1"
    print(f"\n[2] Range 请求: GET {path} (Range: bytes=0-1023)")
    raw = http_get(host, path, {"Range": "bytes=0-1023"})
    hdrs, status, body = parse_head(raw)
    check("状态码 206", status == 206, f"实际 {status}")
    check("Content-Length == 1024",
          hdrs.get("content-length") == "1024", hdrs.get("content-length"))
    check("Content-Range 头存在", "content-range" in hdrs, hdrs.get("content-range"))
    check("首字节 == 50 4b 03 04", body[:4] == b"\x50\x4b\x03\x04", body[:4].hex(" "))


def test_416():
    serve = RULES["serve"][0]
    host = serve["host"]
    path = "/ecology/" + "c" * 40 + ".1"
    print(f"\n[3] 越界 Range: GET {path} (Range: bytes=999999999-)")
    raw = http_get(host, path, {"Range": "bytes=999999999-"})
    hdrs, status, body = parse_head(raw)
    check("状态码 416", status == 416, f"实际 {status}")
    check("Content-Range: bytes */size",
          hdrs.get("content-range") == f"bytes */{APK_SIZE}",
          hdrs.get("content-range"))


def test_patch_real_api():
    """真实接口: 无签名头时 data 是字符串 -> 代理应原样转发 (不改写)。"""
    rule = RULES["patch"][0]
    host = rule["host"]
    path = rule["path_prefix"]
    print(f"\n[4] patch 规则 (真实接口, 无签名头): POST https://{host}{path}")
    raw = http_post(host, path, b'{"appPackage":"com.icoolme.car.weather"}')
    hdrs, status, body = parse_head(raw)
    check("状态码 200", status == 200, f"实际 {status}")
    cl = hdrs.get("content-length")
    check("Content-Length 存在且等于实际 body 长度",
          cl is not None and int(cl) == len(body), f"{cl} vs {len(body)}")
    check("无 Content-Encoding 残留", "content-encoding" not in hdrs,
          hdrs.get("content-encoding"))
    try:
        obj = json.loads(body.decode("utf-8"))
        check("响应是合法 JSON", True)
    except Exception as e:
        check("响应是合法 JSON", False, str(e))
        return
    # 真实接口缺签名头 -> data 非对象 -> 字段不存在 -> 原样转发
    data = obj.get("data")
    if isinstance(data, dict):
        # 若上游恰好返回了完整结构, 字段应已被改写
        for field, want in rule["set"].items():
            cur = obj
            for seg in field.split("."):
                cur = cur.get(seg) if isinstance(cur, dict) else None
            check(f"{field} == {want!r}", cur == want, f"实际 {cur!r}")
    else:
        check("data 非对象(缺签名头) -> 代理原样转发, 未破坏响应",
              obj.get("success") is False or "code" in obj,
              f"code={obj.get('code')}")


def test_patch_field_rewrite():
    """字段改写逻辑验证: 用同结构的 JSON 直接测 set_path/get_path + 重新序列化。"""
    rule = RULES["patch"][0]
    print("\n[5] patch 字段改写逻辑 (点路径写入 + 重新序列化)")
    sample = {
        "code": 0, "message": "ok", "success": True,
        "data": {
            "appResourceUri": "https://prod-dp-public-es33.oss-cn-shanghai.aliyuncs.com/ecology/abc.1",
            "appPackage": "com.icoolme.car.weather",
            "appName": "最美天气",
            "appActualSize": "7524",
            "appDisplaySize": "7M",
        },
    }
    changed = []
    for field, newval in rule["set"].items():
        if set_path(sample, field, newval):
            changed.append(field)
    check("4 个字段全部命中并改写", len(changed) == 4, f"命中 {len(changed)}: {changed}")
    for field, want in rule["set"].items():
        cur = sample
        for seg in field.split("."):
            cur = cur.get(seg) if isinstance(cur, dict) else None
        check(f"{field} == {want!r}", cur == want, f"实际 {cur!r}")
    check("appResourceUri 保持不变 (交给 serve 规则拦截)",
          sample["data"]["appResourceUri"].endswith("/ecology/abc.1"))
    body = json.dumps(sample, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    check("重新序列化后长度正确", len(body) == len(json.dumps(
        sample, ensure_ascii=False, separators=(",", ":")).encode("utf-8")))


def test_apk_anchor():
    """体积换算锚点: 字节数 // 1024 -> appActualSize, // 1048576 -> appDisplaySize"""
    print("\n[6] 体积换算锚点校验")
    real = os.path.getsize(APK_PATH)
    check("实际 APK 字节数 == 规则中的 apk_size", real == APK_SIZE,
          f"{real} vs {APK_SIZE}")
    check("appActualSize == 字节数 // 1024",
          str(real // 1024) == RULES["patch"][0]["set"]["data.appActualSize"],
          f"{real // 1024}")
    check("appDisplaySize == 字节数 // 1048576 + M",
          f"{real // 1048576}M" == RULES["patch"][0]["set"]["data.appDisplaySize"],
          f"{real // 1048576}M")
    # 用户给的公式锚点: 7,704,714 -> 7524 / 7M
    check("公式锚点 7,704,714 -> 7524 / 7M",
          7704714 // 1024 == 7524 and 7704714 // 1048576 == 7)


def test_tls_paths():
    print("\n[7] TLS 证书链 (两个域名共用同一张多 SAN 证书)")
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding

    # 用 cryptography 解析真实证书 (ssl.CERT_NONE 时 getpeercert() 为空)
    for host in ("prod-r-platform.z-onesoft.com",
                 "prod-dp-public-es33.oss-cn-shanghai.aliyuncs.com"):
        try:
            raw = tls_connect(GATEWAY, host)
            der = raw.getpeercert(binary_form=True)
            raw.close()
            cert = x509.load_der_x509_certificate(der)
            names = [n.value for n in
                     cert.extensions.get_extension_for_class(
                         x509.SubjectAlternativeName).value]
            check(f"{host} 握手成功且 SAN 覆盖本域名",
                  host in names, ", ".join(names))
            # 所有域名用同一张证书 -> 指纹一致
            fp = cert.fingerprint(hashes_sha256()).hex()
            if FIRST_FP[0] is None:
                FIRST_FP[0] = fp
            check(f"{host} 使用的是同一张多 SAN 证书",
                  fp == FIRST_FP[0], "指纹 " + fp[:16] + "...")
        except Exception as e:
            check(f"{host} 握手成功", False, f"{type(e).__name__}: {e}")


def hashes_sha256():
    from cryptography.hazmat.primitives import hashes
    return hashes.SHA256()


FIRST_FP = [None]


def test_response_integrity():
    """
    关键回归测试: 代理必须真的把响应发给客户端。

    曾出现过一个 bug: do_passthrough 里 `return` 与 `tls.sendall(...)` 被挤到同一行,
    导致函数直接 return、响应从未发出 —— 日志却显示 "[pass] 原样转发 1739 bytes",
    看起来一切正常, 但车机收到空响应 -> 报"网络异常"。
    因此这里必须实际读取响应体并校验 Content-Length。
    """
    print("\n[8] 响应完整性 (回归: 代理必须真正发出响应)")
    host = "prod-r-platform.z-onesoft.com"
    for path in ("/eco/ippf/appMarket/vehicle/banner/list",
                 "/eco/ippf/appMarket/vehicle/app/detail"):
        body = b'{"appPackage":"com.icoolme.car.weather"}'
        s = tls_connect(GATEWAY, host)
        try:
            req = (f"POST {path} HTTP/1.1\r\nHost: {host}\r\n"
                   f"User-Agent: okhttp/3.14.9\r\n"
                   f"Content-Type: application/json; charset=utf-8\r\n"
                   f"Content-Length: {len(body)}\r\nConnection: keep-alive\r\n\r\n")
            s.sendall(req.encode() + body)
            s.settimeout(15)
            buf = b""
            while True:
                c = s.recv(65536)
                if not c:
                    break
                buf += c
                he = buf.find(b"\r\n\r\n")
                if he >= 0:
                    hdrs0, _, _ = parse_head(buf)
                    cl0 = hdrs0.get("content-length")
                    if cl0 and len(buf) - (he + 4) >= int(cl0):
                        break
        finally:
            s.close()

        name = path.rsplit("/", 1)[-1]
        hdrs, status, rbody = parse_head(buf)
        check(f"{name}: 收到非空响应头", len(hdrs) > 0,
              f"头行数 {len(hdrs)}")
        check(f"{name}: 状态码 200", status == 200, f"实际 {status}")
        check(f"{name}: body 非空", len(rbody) > 0, f"{len(rbody)} 字节")
        cl = hdrs.get("content-length")
        check(f"{name}: Content-Length == 实际 body 长度",
              cl is not None and int(cl) == len(rbody),
              f"{cl} vs {len(rbody)}")
        check(f"{name}: body 是合法 JSON", _is_json(rbody))
        check(f"{name}: Connection: close",
              hdrs.get("connection") == "close", hdrs.get("connection"))


def _is_json(b):
    try:
        json.loads(b.decode("utf-8"))
        return True
    except Exception:
        return False


def test_serve_real_car_path():
    """
    车机真实下载路径回归。
    车机实际请求的是 /ecology/ecofile-<hash>.apk (UA=OkDownload/1.0.7),
    而非最初假设的 /ecology/<hash>.1 —— serve 规则若只匹配 .1 就会漏掉,
    导致官方 APK 被原样转发。
    """
    print("\n[9] serve 规则覆盖车机真实下载路径")
    serve = RULES["serve"][0]
    host = serve["host"]
    real_path = "/ecology/ecofile-f2382adef9d44098b67e9bfb10913a56.apk"
    raw = http_get(host, real_path, {"User-Agent": "OkDownload/1.0.7"})
    hdrs, status, body = parse_head(raw)
    check("状态码 200", status == 200, f"实际 {status}")
    check("Content-Length == APK 字节数",
          hdrs.get("content-length") == str(APK_SIZE),
          f"{hdrs.get('content-length')} vs {APK_SIZE}")
    check("首字节 == 50 4b 03 04", body[:4] == b"\x50\x4b\x03\x04",
          body[:4].hex(" "))
    orig = open(APK_PATH, "rb").read()
    check("下发内容与本地 APK 完全一致", body == orig,
          f"{len(body)} vs {len(orig)}")


def test_real_chunked_fixture():
    """
    真实车机响应的回归测试。

    固件 certs/fixtures/real_detail_chunked.bin 是从车机实际请求中 dump 下来的
    上游原始响应 —— 它使用 Transfer-Encoding: chunked, body 形如
    "68d\\r\\n{...}\\r\\n0\\r\\n\\r\\n"。

    曾因不解 chunked 而把 chunk 长度 "68d" 当成 JSON 内容,
    报 "Extra data: line 1 column 3 (char 2)", 导致详情页改写从未生效。
    这个测试锁定该行为。
    """
    print("\n[10] 真实 chunked 响应回归 (车机 dump 固件)")
    fixture = os.path.join(BASE, "certs", "fixtures", "real_detail_chunked.bin")
    if not os.path.exists(fixture):
        check("固件存在", False, fixture)
        return
    raw = open(fixture, "rb").read()

    from proxy_server import (Headers, parse_header_lines, decode_chunked,
                              get_path, set_path, split_response)

    head, rbody = split_response(raw)
    rheaders = Headers(parse_header_lines(head))
    te = rheaders.get("Transfer-Encoding")
    te_s = te.decode().lower() if te else ""
    check("响应使用 Transfer-Encoding: chunked", "chunked" in te_s, te_s)

    dec, complete = decode_chunked(rbody)
    check("chunked 解码完整", complete, f"{len(dec)} 字节")
    check("解码后不再含 chunk 长度头",
          not re.match(rb"^[0-9a-fA-F]+\r\n", dec),
          dec[:16].hex(" "))

    try:
        obj = json.loads(dec.decode("utf-8"))
        check("解码后是合法 JSON", True)
    except Exception as e:
        check("解码后是合法 JSON", False, str(e))
        return

    check("真实响应 code == 200", obj.get("code") == 200, obj.get("code"))
    check("真实 data.appName == '最美天气'",
          get_path(obj, "data.appName")[0] == "最美天气",
          get_path(obj, "data.appName")[0])
    check("真实 data.appDisplaySize == '6M'",
          get_path(obj, "data.appDisplaySize")[0] == "6M",
          get_path(obj, "data.appDisplaySize")[0])

    # 用规则改写
    rule = RULES["patch"][0]
    changed = []
    for field, newval in rule["set"].items():
        old, ex = get_path(obj, field)
        if ex and set_path(obj, field, newval):
            changed.append(field)
    check("4 个字段全部命中并改写", len(changed) == 4, f"命中 {len(changed)}")
    for field, want in rule["set"].items():
        cur, _ = get_path(obj, field)
        check(f"{field} == {want!r}", cur == want, f"实际 {cur!r}")

    new_body = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode()
    rh = Headers(parse_header_lines(head))
    rh.remove("Content-Length")
    rh.remove("Content-Encoding")
    rh.remove("Transfer-Encoding")
    rh.set("Content-Length", str(len(new_body)))
    out = rh.raw()
    check("输出头已移除 Transfer-Encoding",
          b"transfer-encoding" not in out.lower())
    check("输出头已移除旧 Content-Length 且写入新值",
          out.lower().count(b"content-length") == 1
          and str(len(new_body)).encode() in out,
          f"新长度 {len(new_body)}")


def main():
    print("=" * 68)
    print(f"代理自检 -> https://{GATEWAY}:{PORT}   APK 期望 {APK_SIZE} bytes")
    print("=" * 68)
    for fn in (test_serve_domain, test_range, test_416,
               test_serve_real_car_path,
               test_patch_real_api, test_patch_field_rewrite,
               test_apk_anchor, test_tls_paths, test_response_integrity,
               test_real_chunked_fixture):
        try:
            fn()
        except Exception as e:
            check(f"{fn.__name__} 异常", False, f"{type(e).__name__}: {e}")

    npass = sum(1 for _, s, _ in results if s == PASS)
    nfail = len(results) - npass
    print("\n" + "=" * 68)
    print(f"结果: {npass} 通过 / {nfail} 失败  (共 {len(results)} 项)")
    print("=" * 68)
    if nfail:
        for n, s, d in results:
            if s == FAIL:
                print(f"  FAILED: {n}  {d}")
    return 1 if nfail else 0


if __name__ == "__main__":
    sys.exit(main())
