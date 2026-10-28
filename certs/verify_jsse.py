#!/usr/bin/env python3
"""
证书链兼容性验证 (JSSE / Android 风格)。

用 JDK 的 JSSE TrustManager (与 Android Conscrypt/JSSE 路径构建逻辑接近)
分别以三个候选根 CA 作唯一信任锚, 对网关 443 做**真实 TLS 握手**,
确认车机 (无论系统信任库里有哪个根) 都能验通我们的叶子证书。

前置: certs/JsseTlsClient.java 已编译 (certs/JsseTlsClient.class)
"""
import os
import subprocess
import sys

BASE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(BASE)


def P(rel):
    return os.path.join(ROOT, rel)


GATEWAY = "192.168.137.1"
PORT = 443
SNI = "prod-r-platform.z-onesoft.com"

ANCHORS = [
    ("AAA Certificate Services", P("certs/root_aaa.pem")),
    ("emSign Root TLS CA - G3", P("certs/root_emsign_tls_g3.pem")),
    ("emSign ECC Root CA - G3", P("certs/root_emsign_ecc_g3.pem")),
]


def main():
    if not os.path.exists(P("certs/JsseTlsClient.class")):
        print("[SKIP] JsseTlsClient 未编译, 先运行:")
        print("       javac -encoding UTF-8 -d certs certs/JsseTlsClient.java")
        return 0

    print("=" * 70)
    print(f"JSSE 兼容性验证 -> https://{GATEWAY}:{PORT}  (SNI {SNI})")
    print("=" * 70)
    npass = 0
    for name, path in ANCHORS:
        if not os.path.exists(path):
            print(f"  [SKIP] {name}: 缺少 {path}")
            continue
        try:
            r = subprocess.run(
                ["java", "-cp", P("certs"), "JsseTlsClient",
                 GATEWAY, str(PORT), SNI, path],
                capture_output=True, timeout=60)
            ok = r.returncode == 0
        except Exception as e:
            ok = False
            print(f"  [FAIL] {name}: {type(e).__name__}: {e}")
            continue
        if ok:
            npass += 1
            print(f"  [PASS] 客户端信任 {name}")
        else:
            err = (r.stderr or b"").decode("utf-8", "replace").strip().splitlines()
            hint = err[0][:100] if err else ""
            print(f"  [FAIL] 客户端信任 {name}  {hint}")

    print(f"\n结果: {npass}/{len(ANCHORS)} 个信任库握手成功")
    if npass == len(ANCHORS):
        print("-> 无论车机系统 CA 库含哪个根, 都能验通")
    else:
        print("-> 至少一个根不可用; 若车机握手失败, 见 车机操作清单.md 失败对照表")
    return 0 if npass == len(ANCHORS) else 1


if __name__ == "__main__":
    sys.exit(main())
