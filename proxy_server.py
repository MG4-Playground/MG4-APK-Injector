#!/usr/bin/env python3
"""
车机应用商店 HTTPS 拦截代理 (仅用于本人车辆的自有设备验证)

设计要点
--------
1. 单张多 SAN 证书, 单一 SSLContext, **绝不按 SNI 切换 context**
   (按 SNI 切换会导致握手失败: 服务端在 ClientHello 阶段就要选好证书,
    同一 socket 无法二次握手)
2. serve 规则命中 -> 不回源, 直接下发本地 APK
   支持 Range / 206 / 416 / Content-Length / Accept-Ranges
   按 256KB 分块写, 逐块打进度日志
3. patch 规则命中 -> 正常回源, 把响应 JSON 按点路径改字段, 重新序列化
   删除旧 Content-Length / Content-Encoding / Transfer-Encoding, 写新的 Content-Length
   一个字段都没命中 -> 原样转发
4. 其余请求一律原样转发 (字节级透传)
5. 回源 DNS 自行发 UDP 查询 (223.5.5.5), 不走系统解析器
   否则 hosts 劫持会让回源指回自己 -> 死循环
6. 日志: 改写成功 / 本地投递 / 投递完成, 完成字节数 == APK 大小
"""
import json
import os
import re
import socket
import socketserver
import ssl
import struct
import sys
import threading
import time

BASE = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE, "store_rules.json")
CHAIN_PATH = os.path.join(BASE, "pki", "chain.pem")
KEY_PATH = os.path.join(BASE, "pki", "leaf.key.pem")
LOG_PATH = os.path.join(BASE, "proxy.log")

GATEWAY_IP = "192.168.137.1"
LISTEN_PORT = 443
UPSTREAM_DNS = "223.5.5.5"
CHUNK = 256 * 1024

# 测试实例 (PROXY_PORT 非 443) 写独立日志, 避免污染主代理的 proxy.log
LOG_PATH = os.environ.get("PROXY_LOG") or (
    os.path.join(BASE, "proxy.log")
    if os.environ.get("PROXY_PORT", "443") == "443"
    else os.path.join(BASE, "proxy.test.log")
)

_log_lock = threading.Lock()


def log(msg, level="INFO"):
    ts = time.strftime("%H:%M:%S")
    line = f"[{ts}] [{level}] {msg}"
    with _log_lock:
        print(line, flush=True)
        try:
            with open(LOG_PATH, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except OSError:
            pass


# ------------------------------------------------------------------ 自建 DNS
def dns_resolve(hostname, timeout=5.0):
    """自行发 UDP DNS 查询到 223.5.5.5, 不用系统解析器 (避开 hosts 死循环)。"""
    try:
        qname = b""
        for part in hostname.split("."):
            qname += bytes([len(part)]) + part.encode("idna")
        qname += b"\x00"
        header = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        packet = header + qname + struct.pack(">HH", 1, 1)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(packet, (UPSTREAM_DNS, 53))
            data, _ = sock.recvfrom(4096)
        finally:
            sock.close()

        if len(data) < 12:
            raise OSError("short DNS response")
        qd, an = struct.unpack(">HH", data[4:8])
        if an == 0:
            raise OSError("no DNS answer")
        off = 12
        for _ in range(qd):
            while data[off] != 0:
                off += data[off] + 1
            off += 5
        for _ in range(an):
            if data[off] & 0xC0 == 0xC0:
                off += 2
            else:
                while data[off] != 0:
                    off += data[off] + 1
                off += 1
            rtype, _rclass, _ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
            off += 10
            rdata = data[off:off + rdlen]
            off += rdlen
            if rtype == 1 and rdlen == 4:
                return socket.inet_ntoa(rdata)
        raise OSError("no A record")
    except Exception as e:
        raise OSError(f"DNS resolve failed for {hostname}: {e}")


# --------------------------------------------------------------- 规则处理
def get_path(obj, path):
    """点路径取值: data.appName -> obj['data']['appName']"""
    cur = obj
    for seg in path.split("."):
        if not isinstance(cur, dict) or seg not in cur:
            return None, False
        cur = cur[seg]
    return cur, True


def set_path(obj, path, value):
    """点路径写值, 成功返回 True"""
    segs = path.split(".")
    cur = obj
    for seg in segs[:-1]:
        if not isinstance(cur, dict) or seg not in cur:
            return False
        cur = cur[seg]
    if not isinstance(cur, dict) or segs[-1] not in cur:
        return False
    cur[segs[-1]] = value
    return True


class Rules:
    def __init__(self, path):
        with open(path, "r", encoding="utf-8") as f:
            self.raw = json.load(f)
        self.serve = self.raw.get("serve", [])
        self.patch = self.raw.get("patch", [])
        self.base = os.path.dirname(os.path.abspath(path))   # 规则文件所在目录
        self.apk_path = self.resolve(self.raw.get("apk_path", ""))

    def resolve(self, p):
        """
        把规则里的路径解析成可用的绝对路径。
        相对路径基于**规则文件所在目录** (即包根目录), 这样整个包可以随意搬走。
        绝对路径原样使用。
        """
        if not p:
            return p
        if os.path.isabs(p):
            return p
        return os.path.normpath(os.path.join(self.base, p))

    def match_serve(self, host, path):
        for r in self.serve:
            if r.get("host") and r["host"] != host:
                continue
            pat = r.get("path_prefix") or r.get("path_regex")
            if pat:
                if r.get("path_regex"):
                    if not re.search(pat, path):
                        continue
                elif not path.startswith(pat):
                    continue
            suf = r.get("path_suffix")
            if suf and not path.split("?")[0].endswith(suf):
                continue
            return r
        return None

    def match_patch(self, host, path, method):
        for r in self.patch:
            if r.get("host") and r["host"] != host:
                continue
            if r.get("method") and r["method"].upper() != method.upper():
                continue
            pat = r.get("path_prefix") or r.get("path_regex")
            if pat:
                if r.get("path_regex"):
                    if not re.search(pat, path):
                        continue
                elif not path.startswith(pat):
                    continue
            return r
        return None


# --------------------------------------------------------------- HTTP 解析
class Headers:
    def __init__(self, raw_lines):
        """raw_lines: 形如 [b"Host: example.com", ...] 的原始头行列表。"""
        self.items = []
        for line in raw_lines:
            if b":" not in line:
                continue
            k, v = line.split(b":", 1)
            self.items.append((k.strip(), v.strip()))

    @classmethod
    def from_pairs(cls, pairs):
        """从 [(b"Host", b"example.com"), ...] 构造 (便于测试与脚本调用)。"""
        h = cls([])
        h.items = [(k if isinstance(k, bytes) else k.encode(),
                    v if isinstance(v, bytes) else v.encode()) for k, v in pairs]
        return h

    def get(self, name, default=None):
        for k, v in self.items:
            if k.lower() == name.lower().encode():
                return v
        return default

    def remove(self, name):
        n = name.lower().encode()
        self.items = [(k, v) for k, v in self.items if k.lower() != n]

    def set(self, name, value):
        n = name.lower().encode()
        self.items = [(k, v) for k, v in self.items if k.lower() != n]
        self.items.append((n, value.encode() if isinstance(value, str) else value))

    def raw(self):
        return b"\r\n".join(k + b": " + v for k, v in self.items)


def read_line(rfile):
    line = rfile.readline()
    if not line:
        return None
    return line.rstrip(b"\r\n")


def read_headers(rfile):
    lines = []
    while True:
        line = rfile.readline()
        if not line or line in (b"\r\n", b"\n"):
            break
        lines.append(line.rstrip(b"\r\n"))
    return Headers(lines)


# --------------------------------------------------------------- 上游请求
def upstream_request(method, host, path, headers, body, port=None, ip=None,
                     scheme="https"):
    """
    用自建 DNS 解析真实 IP, 直连上游 (绕过 hosts 劫持)。
    scheme="http" 时走明文 (仅用于本地模拟上游的端到端测试)。
    """
    ip = ip or dns_resolve(host)
    if scheme == "http":
        port = port or 80
        sock = socket.create_connection((ip, port), timeout=20)
        sock.settimeout(20)
        conn = sock
    else:
        port = port or 443
        sock = socket.create_connection((ip, port), timeout=20)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # 回源用系统信任即可, 这里不校验以简化
        conn = ctx.wrap_socket(sock, server_hostname=host)
    tls = conn
    req = f"{method} {path} HTTP/1.1\r\n".encode()
    hdr = headers.raw()
    tls.sendall(req + hdr + b"\r\n\r\n" + (body or b""))

    # 关键: 上游会回 Connection: keep-alive, 连接不会主动关闭。
    # 若一直读到 EOF, 会一直等到 socket 超时 -> "read operation timed out",
    # 导致响应发不回车机 (表现为应用商店加载不出来)。
    # 这里按 Content-Length / chunked 精确读取, 读够即停。
    buf = b""
    deadline = time.time() + 25
    while time.time() < deadline:
        try:
            chunk = tls.recv(65536)
        except socket.timeout:
            break
        except (ssl.SSLError, OSError):
            break
        if not chunk:
            break
        buf += chunk
        if _response_complete(buf):
            break
    tls.close()
    return buf


def _response_complete(buf):
    """
    判断响应是否已收完整。

    优先按 Content-Length / chunked 判断; 若响应体是 JSON, 再做一次
    JSON 完整性校验 —— 因为 Content-Length 有时与实际载荷不符 (CDN 改写、
    中间层压缩等), 只看长度会在数据还没收全时就返回, 导致下游解析出
    "Extra data" 之类的怪错误。
    """
    idx = buf.find(b"\r\n\r\n")
    if idx < 0:
        return False
    head = buf[:idx].decode("latin-1", errors="replace")
    body = buf[idx + 4:]

    lower = head.lower()
    if "transfer-encoding: chunked" in lower:
        return body.rstrip().endswith(b"0") and b"\r\n0\r\n" in body + b"\r\n"
    m = re.search(r"content-length:\s*(\d+)", lower)
    if m:
        need = int(m.group(1))
        if len(body) < need:
            return False
        # 长度够了: 若看起来是 JSON, 额外确认能完整解析
        if len(body) >= need:
            dec = _try_decode_json(body[:need])
            if dec is None and body[:1] in (b"{", b"["):
                # 是 JSON 开头但解析失败 -> 可能还没收全, 继续读
                return False
            return True
    # 无长度信息: 只能等 EOF, 由调用方的 socket 超时兜底
    return False


def _try_decode_json(data):
    """尝试把 data 解成 JSON; 失败返回 None。"""
    import json as _json
    if not data:
        return None
    # 可能是 gzip/br/deflate
    for dec in (lambda d: d,
                _maybe_gunzip,
                _maybe_brotli,
                _maybe_inflate):
        try:
            out = dec(data)
            if out is None:
                continue
            return _json.loads(out.decode("utf-8"))
        except Exception:
            continue
    return None


def _maybe_gunzip(data):
    import gzip
    return gzip.decompress(data)


def _maybe_brotli(data):
    import brotli
    return brotli.decompress(data)


def _maybe_inflate(data):
    import zlib
    return zlib.decompress(data)


def split_response(raw):
    """返回 (head_bytes, body_bytes)"""
    idx = raw.find(b"\r\n\r\n")
    if idx < 0:
        return raw, b""
    return raw[:idx + 4], raw[idx + 4:]


def parse_header_lines(head):
    """
    从 head 字节中提取头部行列表 (不含状态行, 不含结尾空行)。
    注意: 不能用 head.split(b"\r\\n")[1:-2] —— 那样会在响应头行数少时误删真实头。
    """
    if b"\r\n\r\n" in head:
        head = head[:head.find(b"\r\n\r\n")]
    lines = head.split(b"\r\n")
    return [l for l in lines[1:] if l.strip()]


def decode_chunked(body):
    """
    解 chunked 传输编码, 返回 (解码后数据, 是否完整)。

    必须做这一步: 真实详情接口 (Kong + CDN) 返回的是
    "Transfer-Encoding: chunked", body 形如 "68d\r\n{...}\r\n0\r\n\r\n"。
    不解开就直接当 JSON 解析, 会把 chunk 长度 "68d" 当成 JSON 内容,
    报 "Extra data: line 1 column 3 (char 2)"。
    """
    out = []
    pos = 0
    n = len(body)
    CRLF = b"\r\n"
    while pos < n:
        nl = body.find(CRLF, pos)
        if nl < 0:
            break
        size_line = body[pos:nl].split(b";")[0].strip()
        try:
            size = int(size_line, 16)
        except ValueError:
            return b"", False
        pos = nl + 2
        if size == 0:
            return b"".join(out), True
        out.append(body[pos:pos + size])
        pos += size
        if body[pos:pos + 2] == CRLF:
            pos += 2
    return b"".join(out), False



def fix_connection_header(raw):
    """
    上游返回 Connection: keep-alive, 但本代理每个请求处理完就关闭连接。
    若把 keep-alive 原样透传给车机, 车机会复用这条已被我方关闭的连接,
    下一次请求就会失败 —— 表现为"应用商店加载不出来"。
    因此统一改成 Connection: close, 让车机每���请求重连。
    """
    idx = raw.find(b"\r\n\r\n")
    if idx < 0:
        return raw
    head = raw[:idx]
    body = raw[idx + 4:]
    lines = head.split(b"\r\n")
    out = []
    for ln in lines[1:]:
        if b":" in ln and ln.split(b":", 1)[0].strip().lower() == b"connection":
            continue
        out.append(ln)
    out.append(b"Connection: close")
    return b"\r\n".join(lines[:1] + out) + b"\r\n\r\n" + body


# --------------------------------------------------------------- 主处理器
class Handler(socketserver.BaseRequestHandler):
    rules = None
    ssl_ctx = None

    def handle(self):
        try:
            # 加大发送缓冲, 加速大文件下发 (150MB APK)
            try:
                self.request.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                self.request.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1 << 20)
            except OSError:
                pass
            tls = self.ssl_ctx.wrap_socket(self.request, server_side=True)
        except Exception as e:
            log(f"TLS 握手失败: {e}", "ERROR")
            return
        try:
            self.serve_http(tls)
        except Exception as e:
            log(f"处理请求异常: {type(e).__name__}: {e}", "ERROR")
        finally:
            try:
                tls.close()
            except OSError:
                pass

    # ---------------------------------------------------------- HTTP 主循环
    def serve_http(self, tls):
        rfile = tls.makefile("rb")
        while True:
            req_line = read_line(rfile)
            if not req_line:
                return
            parts = req_line.split()
            if len(parts) < 2:
                return
            method, path = parts[0].decode(), parts[1].decode()
            headers = read_headers(rfile)

            body = b""
            te = headers.get("Transfer-Encoding", b"").decode().lower()
            clen = headers.get("Content-Length")
            if "chunked" in te:
                # chunked 请求体: 读到结束块为止
                chunks = []
                while True:
                    size_line = read_line(rfile)
                    if size_line is None:
                        break
                    try:
                        size = int(size_line.split(b";")[0].strip(), 16)
                    except ValueError:
                        break
                    if size == 0:
                        read_line(rfile)  # 末尾 CRLF
                        break
                    try:
                        chunks.append(rfile.read(size))
                        rfile.read(2)  # chunk 后的 CRLF
                    except OSError:
                        break
                body = b"".join(chunks)
            elif clen:
                try:
                    body = rfile.read(int(clen))
                except (ValueError, OSError):
                    body = b""

            host = headers.get("Host", b"").decode() or \
                host_from_path(path)
            host = host.split(":")[0]

            log(f"--> {method} {host}{path}  UA={headers.get('User-Agent', b'-').decode()[:40]}")

            # 规则 1: serve -> 本地 APK
            serve_rule = self.rules.match_serve(host, path)
            if serve_rule:
                self.do_serve(tls, host, path, headers, serve_rule)
                return

            # 规则 2: patch -> 回源改写
            rule = self.rules.match_patch(host, path, method)
            if rule:
                self.do_patch(tls, host, path, method, headers, body, rule)
                return

            # 其余: 原样转发
            self.do_passthrough(tls, host, path, method, headers, body)
            return

    # ------------------------------------------------------------ serve 规则
    def do_serve(self, tls, host, path, headers, rule=None):
        rule = rule or {}
        apk = self.rules.resolve(rule.get("file") or self.rules.apk_path)
        if not os.path.exists(apk):
            log(f"serve 命中但 APK 不存在: {apk}", "ERROR")
            tls.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
            return
        size = os.path.getsize(apk)
        log(f"[serve] 规则命中 {host}{path} -> 本地 APK {os.path.basename(apk)} ({size} bytes)")

        range_hdr = headers.get("Range")
        start, end = 0, size - 1
        partial = False
        if range_hdr:
            rng = range_hdr.decode(errors="replace")
            m = re.match(r"bytes=(\d*)-(\d*)", rng)
            if m:
                s, e = m.group(1), m.group(2)
                if s == "" and e == "":
                    pass
                elif s == "":  # bytes=-N  (最后 N 字节)
                    n = int(e)
                    start = max(0, size - n)
                    end = size - 1
                    partial = True
                else:
                    start = int(s)
                    end = int(e) if e else size - 1
                    if start >= size:
                        # 416
                        tls.sendall(
                            b"HTTP/1.1 416 Range Not Satisfiable\r\n"
                            b"Content-Range: bytes */" + str(size).encode() + b"\r\n"
                            b"Content-Length: 0\r\n"
                            b"Accept-Ranges: bytes\r\n\r\n")
                        log(f"[serve] Range 越界 -> 416 (start={start} size={size})")
                        return
                    end = min(end, size - 1)
                    partial = True

        length = end - start + 1
        head = [
            b"HTTP/1.1 206 Partial Content" if partial else b"HTTP/1.1 200 OK",
            b"Content-Type: application/vnd.android.package-archive",
            b"Content-Length: " + str(length).encode(),
            b"Accept-Ranges: bytes",
            b"Connection: close",
        ]
        if partial:
            head.append(b"Content-Range: bytes " +
                        f"{start}-{end}/{size}".encode())
        tls.sendall(b"\r\n".join(head) + b"\r\n\r\n")

        sent = 0
        # 性能: 256KB 逐块 sendall 在大文件(150MB+)上会因为 TLS 记录与
        # 逐次等待确认而非常慢(实测 195s)。这里用 1MB 读块 + 4MB 批量发送,
        # 进度日志按 ~10% 打印一次, 既快又不刷屏。
        BATCH = 4 * 1024 * 1024
        pending = bytearray()
        next_log = 10
        with open(apk, "rb") as f:
            f.seek(start)
            while sent < length:
                n = min(CHUNK, length - sent)
                buf = f.read(n)
                if not buf:
                    break
                pending += buf
                sent += len(buf)
                if len(pending) >= BATCH or sent >= length:
                    tls.sendall(bytes(pending))
                    pending = bytearray()
                pct = sent * 100 // length
                if pct >= next_log:
                    log(f"[serve] 投递进度 {sent}/{length} bytes ({pct}%)")
                    next_log = pct + 10
        if pending:
            tls.sendall(bytes(pending))

        if partial:
            log(f"[serve] 投递完成 {sent} bytes (206 部分内容, Range {start}-{end})")
        else:
            log(f"[serve] 投递完成 {sent} bytes == APK 大小 {size} "
                f"{'OK' if sent == size else 'MISMATCH!'}")

    # ------------------------------------------------------------ patch 规则
    def do_patch(self, tls, host, path, method, headers, body, rule):
        # 回源地址可被规则覆盖 (upstream_host/upstream_port), 便于端到端测试
        up_host = rule.get("upstream_host") or host
        up_port = rule.get("upstream_port")
        up_ip = rule.get("upstream_ip")
        up_scheme = rule.get("upstream_scheme", "https")
        try:
            raw = upstream_request(method, up_host, path, headers, body,
                                   port=up_port, ip=up_ip, scheme=up_scheme)
        except Exception as e:
            log(f"patch 回源失败: {e}", "ERROR")
            tls.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            return

        head, rbody = split_response(raw)
        status_line = head.split(b"\r\n", 1)[0]
        rheaders = Headers(parse_header_lines(head))

        # 调试: 落盘上游原始响应 (PROXY_DUMP=1), 便于排查解析问题
        if os.environ.get("PROXY_DUMP"):
            try:
                import hashlib
                dump = os.path.join(BASE, "dump")
                os.makedirs(dump, exist_ok=True)
                tag = hashlib.sha256(path.encode()).hexdigest()[:8]
                with open(os.path.join(dump, f"{tag}.bin"), "wb") as f:
                    f.write(raw)
                log(f"[dump] 上游原始响应已存 dump/{tag}.bin ({len(raw)} bytes)")
            except Exception as e:
                log(f"[dump] 落盘失败: {e}", "WARN")

        # 传输编码: 先解 chunked (Transfer-Encoding: chunked)。
        # 真实详情接口就是 chunked, 不解开会把 "68d\r\n{...}" 的 chunk 长度
        # 当成 JSON 内容, 报 "Extra data: line 1 column 3 (char 2)"。
        te = rheaders.get("Transfer-Encoding")
        te_s = te.decode().lower() if te else ""
        if "chunked" in te_s:
            dec_body, complete = decode_chunked(rbody)
            if complete:
                rbody = dec_body
                log(f"[patch] 已解 chunked 传输编码 ({len(rbody)} bytes)")
            else:
                log(f"[patch] chunked 不完整, 保留原始 body", "WARN")

        # 内容编码: 不完全依赖 Content-Encoding 声明 (CDN 可能声明与实际不符),
        # 依次尝试 原文 / gzip / brotli / deflate, 取第一个能解析成 JSON 的。
        enc = rheaders.get("Content-Encoding")
        enc_s = enc.decode().lower() if enc else ""
        obj = None
        cands = []
        if not enc_s:
            cands.append(("原文", lambda d: d))
        else:
            if "gzip" in enc_s:
                cands.append(("gzip", _maybe_gunzip))
            if "br" in enc_s:
                cands.append(("brotli", _maybe_brotli))
            if "deflate" in enc_s:
                cands.append(("deflate", _maybe_inflate))
        # 兜底: 无论声明了什么, 都把所有方式试一遍
        cands += [("原文", lambda d: d), ("gzip", _maybe_gunzip),
                  ("brotli", _maybe_brotli), ("deflate", _maybe_inflate)]

        used = None
        for label, fn in cands:
            try:
                out = fn(rbody)
                if out is None:
                    continue
                obj = json.loads(out.decode("utf-8"))
                used = label
                break
            except Exception:
                continue

        if obj is None:
            log(f"响应不是 JSON (enc={enc_s!r}), 原样转发: "
                f"body前32字节={rbody[:32]!r}", "WARN")
            tls.sendall(fix_connection_header(raw))
            return
        if used != "原文":
            log(f"响应体以 {used} 方式解码 (声明 enc={enc_s!r})")

        changed = []
        for field, newval in rule.get("set", {}).items():
            old, exists = get_path(obj, field)
            if not exists:
                continue
            if set_path(obj, field, newval):
                changed.append(f"{field}: {old!r} -> {newval!r}")

        if not changed:
            log("patch 未命中任何字段, 原样转发", "WARN")
            tls.sendall(fix_connection_header(raw))
            return

        new_body = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

        # 删旧 Content-Length / Content-Encoding / Transfer-Encoding, 写新的
        rheaders.remove("Content-Length")
        rheaders.remove("Content-Encoding")
        rheaders.remove("Transfer-Encoding")
        rheaders.set("Content-Length", str(len(new_body)))
        rheaders.set("Content-Type", "application/json; charset=utf-8")
        rheaders.set("Connection", "close")

        out_head = status_line + b"\r\n" + rheaders.raw() + b"\r\n\r\n"
        tls.sendall(out_head + new_body)

        log(f"[patch] 改写成功 {len(changed)} 个字段: " + "; ".join(changed))
        log(f"[patch] 原 {len(rbody)} bytes -> 新 {len(new_body)} bytes, "
            f"已重写 Content-Length={len(new_body)}")

    # ------------------------------------------------------- 原样转发
    def do_passthrough(self, tls, host, path, method, headers, body):
        try:
            raw = upstream_request(method, host, path, headers, body)
        except Exception as e:
            log(f"转发失败: {e}", "ERROR")
            tls.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            return
        tls.sendall(fix_connection_header(raw))
        log(f"[pass] 原样转发 {method} {host}{path} ({len(raw)} bytes)")


def host_from_path(path):
    if path.startswith("http://") or path.startswith("https://"):
        m = re.match(r"https?://([^/]+)", path)
        if m:
            return m.group(1)
    return ""


class Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


def main():
    rules = Rules(os.environ.get("PROXY_RULES", CONFIG_PATH))
    Handler.rules = rules

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # 单张多 SAN 证书 + 单一 context, 不按 SNI 切换
    ctx.load_cert_chain(certfile=CHAIN_PATH, keyfile=KEY_PATH)
    try:
        ctx.set_alpn_protocols(["http/1.1"])
    except NotImplementedError:
        pass
    Handler.ssl_ctx = ctx

    gateway = os.environ.get("PROXY_GATEWAY", GATEWAY_IP)
    port = int(os.environ.get("PROXY_PORT", LISTEN_PORT))
    srv = Server((gateway, port), Handler)
    log(f"代理已启动: https://{gateway}:{port}  (单 SSLContext, 多 SAN)")
    log(f"serve 规则 {len(rules.serve)} 条 / patch 规则 {len(rules.patch)} 条")
    log(f"APK: {rules.apk_path}")
    log("回源 DNS: 自建 UDP -> " + UPSTREAM_DNS + " (不走系统解析器)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        log("停止")
        srv.shutdown()


if __name__ == "__main__":
    main()
