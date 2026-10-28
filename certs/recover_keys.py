#!/usr/bin/env python3
"""
还原 eMudhra 2025-04-30 KGC 缺陷产生的 8 张弱密钥中间证书的 ECDSA P-384 私钥。

方法:
  1) 从证书 SPKI 解出公钥点 Q = (x, y)
  2) 枚举 d = 1 .. 2**20, 计算 d*G (雅可比坐标增量加法, 避免逐次模逆)
  3) 命中即 d*G == Q, 用 cryptography 二次校验 (derive_private_key 后比对公钥坐标)
  4) 私钥只落盘 (PKCS8 PEM), 不打印

产物:
  keys/<SLUG>__<TAG>.key.pem        还原出的中间证书私钥 (PKCS8, EC PRIVATE KEY)
  keys/_recovery.json               每个 SPKI 的 d 值与命中证书名 (仅落盘)
"""
import json
import os
import re
import sys

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    load_pem_private_key,
)
from cryptography import x509

HERE = os.path.dirname(os.path.abspath(__file__))
CERTS = os.path.abspath(os.path.join(HERE, "..", "certs"))
KEYDIR = os.path.join(HERE, "keys")
INTER = os.path.join(CERTS, "inter")
LIM = 1 << 20


# ---------------------------------------------------------------- P-384 参数
# NIST P-384 / secp384r1 (RFC 6218)
P = int(
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE"
    "FFFFFFFF0000000000000000FFFFFFFF",
    16,
)
A = P - 3
B = int("B3312FA7E23EE7E4988E056BBE3F82D219181D9C6EFE814112B03385A", 16)
GX = int(
    "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A38"
    "5502F25DBF55296C3A545E3872760AB7",
    16,
)
GY = int(
    "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C0"
    "0A60B1CE1D7E819D7A431D7C90EA0E5F",
    16,
)
ORDER = int(
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF"
    "581A0DB248B0A77AECEC196ACCC52973",
    16,
)


def load_curve():
    return ec.SECP384R1(), P, A, B, GX, GY, ORDER


CURVE, P, A, B, GX, GY, ORDER = load_curve()


def _dbl(X1, Y1, Z1):
    """雅可比坐标倍点 (a = -3 通用公式)。"""
    if Y1 == 0 or Z1 == 0:
        return (0, 1, 0)
    # S = 4*X1*Y1^2
    YY = (Y1 * Y1) % P
    S = (4 * X1 * YY) % P
    # M = 3*(X1 - Z1^2)*(X1 + Z1^2)  (a=-3 简化)
    ZZ = (Z1 * Z1) % P
    M = (3 * (X1 - ZZ) * (X1 + ZZ)) % P
    # X3 = M^2 - 2S
    X3 = (M * M - 2 * S) % P
    # Y3 = M*(S - X3) - 8*Y1^4
    Y4 = (YY * YY) % P
    Y3 = (M * (S - X3) - 8 * Y4) % P
    # Z3 = 2*Y1*Z1
    Z3 = (2 * Y1 * Z1) % P
    return (X3, Y3, Z3)


def _add_mixed(X1, Y1, Z1, x2, y2):
    """雅可比 + 仿射 混合加法。"""
    if Z1 == 0:
        return (x2, y2, 1)
    Z1Z1 = (Z1 * Z1) % P
    U2 = (x2 * Z1Z1) % P
    S2 = (y2 * Z1 * Z1Z1) % P
    H = (U2 - X1) % P
    r = (S2 - Y1) % P
    if H == 0:
        if r == 0:
            return _dbl(X1, Y1, Z1)
        return (0, 1, 0)  # 无穷远
    HH = (H * H) % P
    HHH = (H * HH) % P
    V = (X1 * HH) % P
    X3 = (r * r - HHH - 2 * V) % P
    Y3 = (r * (V - X3) - Y1 * HHH) % P
    Z3 = (Z1 * H) % P
    return (X3, Y3, Z3)


def _to_affine(X, Y, Z):
    if Z == 0:
        return None
    zinv = pow(Z, P - 2, P)
    zinv2 = (zinv * zinv) % P
    return ((X * zinv2) % P, (Y * zinv2 * zinv) % P)


def recover_d(qx, qy, limit=LIM):
    """枚举 d, 返回首个使 d*G == (qx,qy) 的 d。"""
    X, Y, Z = GX, GY, 1  # 1*G
    for d in range(1, limit + 1):
        aff = _to_affine(X, Y, Z)
        if aff is not None and aff[0] == qx and aff[1] == qy:
            return d
        X, Y, Z = _add_mixed(X, Y, Z, GX, GY)
    return None


def pubkey_point(cert):
    spki = cert.public_key()
    nums = spki.public_numbers()
    return nums.x, nums.y


def selftest():
    """用 cryptography 派生 d=1,2,3 的公钥, 与本地雅可比实现比对。"""
    for d in (1, 2, 3, 7, 12345):
        sk = ec.derive_private_key(d, CURVE)
        pn = sk.public_key().public_numbers()
        # 用本地实现算 d*G
        X, Y, Z = GX, GY, 1
        for _ in range(d - 1):
            X, Y, Z = _add_mixed(X, Y, Z, GX, GY)
        aff = _to_affine(X, Y, Z)
        assert aff is not None and aff[0] == pn.x and aff[1] == pn.y, \
            f"curve selftest failed at d={d}"
    print("[SELFTEST] 雅可比 P-384 实现与 cryptography 一致 (d=1,2,3,7,12345)")


def main():
    os.makedirs(KEYDIR, exist_ok=True)
    selftest()
    files = sorted(
        f for f in os.listdir(INTER)
        if f.endswith(".pem") and not f.endswith(".part0.pem")
    )
    # 同一 SPKI 只恢复一次 (emSign 版与 AAA 交叉版共享 SPKI)
    results = {}
    plan = []
    for fn in files:
        path = os.path.join(INTER, fn)
        cert = x509.load_pem_x509_certificate(open(path, "rb").read())
        spki = cert.public_key().public_bytes(
            Encoding.DER, __import__(
                "cryptography.hazmat.primitives.serialization",
                fromlist=["PublicFormat"]).PublicFormat.SubjectPublicKeyInfo
        )
        import hashlib
        spki_sha = hashlib.sha256(spki).hexdigest().upper()
        plan.append((fn, path, cert, spki_sha))

    seen = {}
    for fn, path, cert, spki_sha in plan:
        if spki_sha in seen:
            results[fn] = dict(seen[spki_sha], reused_from=seen[spki_sha]["file"])
            continue
        qx, qy = pubkey_point(cert)
        d = recover_d(qx, qy)
        if d is None:
            print(f"[FAIL] {fn}: d not found in 1..2**20")
            results[fn] = {"file": fn, "found": False}
            continue
        # 二次校验: 用 cryptography 重新派生公钥并比对坐标
        sk = ec.derive_private_key(d, CURVE)
        pn = sk.public_key().public_numbers()
        ok = (pn.x == qx and pn.y == qy)
        # 落盘私钥
        kpath = os.path.join(KEYDIR, fn.replace(".pem", ".key.pem"))
        with open(kpath, "wb") as f:
            f.write(sk.private_bytes(
                Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
        entry = {
            "file": fn,
            "found": True,
            "verified": ok,
            "spki_sha256": spki_sha,
            "key_file": os.path.basename(kpath),
            "d_file": "keys/_secrets.json",
        }
        results[fn] = entry
        seen[spki_sha] = entry
        print(f"[HIT ] {fn}: d recovered, cross-check={'PASS' if ok else 'FAIL'} "
              f"-> {os.path.basename(kpath)}")

    # d 值单独落盘, 不打印到 stdout
    secrets = {}
    for fn, path, cert, spki_sha in plan:
        if results.get(fn, {}).get("found"):
            secrets.setdefault(spki_sha, {})[fn] = None
    # 从恢复出的私钥文件反推 d (仅写文件)
    for spki_sha, dmap in secrets.items():
        for fn in list(dmap):
            kp = os.path.join(KEYDIR, fn.replace(".pem", ".key.pem"))
            if os.path.exists(kp):
                sk = load_pem_private_key(open(kp, "rb").read(), password=None)
                dmap[fn] = sk.private_numbers().private_value
    with open(os.path.join(KEYDIR, "_secrets.json"), "w") as f:
        json.dump(secrets, f, indent=2)

    summary = {
        "total_files": len(files),
        "unique_spki": len(seen),
        "recovered": sum(1 for v in results.values() if v.get("found")),
        "all_verified": all(v.get("verified", True) for v in results.values()),
        "results": results,
    }
    with open(os.path.join(KEYDIR, "_recovery.json"), "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\n共 {len(files)} 张中间证书副本 / {len(seen)} 个独立 SPKI, "
          f"恢复 {summary['recovered']} 个, 交叉校验全部通过: {summary['all_verified']}")
    return 0 if summary["recovered"] == len(seen) and summary["all_verified"] else 1


if __name__ == "__main__":
    sys.exit(main())
