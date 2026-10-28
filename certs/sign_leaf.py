#!/usr/bin/env python3
"""
用还原出的 eMudhra 弱私钥中间证书签发叶子证书。

产物:
  chain.pem    叶子 + 中间 (AAA Certificate Services 交叉签名版), 供服务端下发
  leaf.key.pem 叶子私钥 (PKCS8)

有效期: 从一年前起算两年 (notBefore = now - 1y, notAfter = notBefore + 2y)
       —— 覆盖车机时钟不准 +-1 年的偏差。
"""
import datetime as dt
import json
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import NameOID

HERE = os.path.dirname(os.path.abspath(__file__))
CERTS = os.path.abspath(os.path.join(HERE, "..", "certs"))
KEYS = os.path.join(CERTS, "keys")
INTER = os.path.join(CERTS, "inter")
OUT = os.path.abspath(os.path.join(HERE, "..", "pki"))
os.makedirs(OUT, exist_ok=True)

# 选用的中间证书: OV TLS CA - G3C (AAA Certificate Services 交叉签名版)
# 理由: AAA Certificate Services 是 Android/Windows/Mozilla 长期内置的老根,
#       车机系统信任库命中概率最高。
INTER_SLUG = "EM_OV_TLS_CA___G3C__aaa"

# chain.pem 组成 (经 JSSE/Android 风格真实握手矩阵验证, 3/3 信任库全覆盖):
#   1) leaf                     —— 本脚本签发, SAN 覆盖两个域名
#   2) EM OV TLS CA - G3C (AAA 交叉签名版)  —— 通往 AAA Certificate Services
#   3) EM OV TLS CA - G3C (emSign 签发版)  —— 通往 emSign Root TLS CA - G3
#   4) emSign Root TLS CA - G3 (由 emSign ECC Root CA - G3 交叉签名)
#        -> 通往 emSign ECC Root CA - G3
#
# 为什么 2 和 3 可以共存:
#   两版 intermediate 的 **subject 完全相同** (EM OV TLS CA - G3C), 但 issuer 不同。
#   JSSE/Conscrypt 的路径构建会回溯尝试备选分支, 因此两个根库都能命中;
#   而只发其中一版时, 另一族根库就无法建链。第 4 张让 emSign ECC Root 也可达。
#
# 注意: 第 4 张虽然与客户端信任锚可能同名, 但因为它不是自签 (issuer 是
#   emSign ECC Root CA - G3), 不会造成路径歧义 —— 这是实测 3/3 的必要条件。
EXTRA_CERTS = [
    "chainpart1.pem",   # EM OV TLS CA - G3C (emSign Root TLS CA - G3 签发)
    "chainpart2.pem",   # emSign Root TLS CA - G3 (emSign ECC Root CA - G3 交叉签名)
]

DOMAINS = [
    "prod-r-platform.z-onesoft.com",
    "prod-dp-public-es33.oss-cn-shanghai.aliyuncs.com",
]


def ensure_extra_certs():
    """
    从 chains.zip 自动提取需要的中间证书, 使本脚本自包含 (不依赖手工生成的
    chainpart*.pem 中间文件)。

    chains/ov-g3c-emudhra.we-have-a-problem.com.pem 的结构:
      part0 = 该测试站的叶子 (忽略)
      part1 = EM OV TLS CA - G3C (由 emSign Root TLS CA - G3 签发)
      part2 = emSign Root TLS CA - G3 (由 emSign ECC Root CA - G3 交叉签名)
    """
    import re
    import zipfile

    zip_path = os.path.join(CERTS, "chains.zip")
    if not os.path.exists(zip_path):
        print("[WARN] 找不到 chains.zip, 跳过追加链证书")
        return
    z = zipfile.ZipFile(zip_path)
    data = z.read("chains/ov-g3c-emudhra.we-have-a-problem.com.pem").decode()
    parts = re.findall(
        r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", data, re.S)
    for i, c in enumerate(parts):
        p = os.path.join(CERTS, f"chainpart{i}.pem")
        with open(p, "w") as f:
            f.write(c.strip() + "\n")


def main():
    ensure_extra_certs()
    inter_pem = open(os.path.join(INTER, INTER_SLUG + ".pem"), "rb").read()
    inter = x509.load_pem_x509_certificate(inter_pem)
    inter_key = serialization.load_pem_private_key(
        open(os.path.join(KEYS, INTER_SLUG + ".key.pem"), "rb").read(), None
    )

    # 校验: 还原出的私钥必须匹配中间证书的公钥
    ipn = inter.public_key().public_numbers()
    kpn = inter_key.public_key().public_numbers()
    assert (ipn.x, ipn.y) == (kpn.x, kpn.y), "中间证书私钥/公钥不匹配"
    print(f"[OK] 中间证书 {inter.subject.rfc4514_string()}")
    print(f"     签发者 {inter.issuer.rfc4514_string()}")
    print(f"     私钥与公钥坐标一致 (d 已正确还原)")

    # 叶子密钥: RSA 2048 (兼容老车机 TLS 密码套件最广)
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    now = dt.datetime.now(dt.timezone.utc)
    not_before = now - dt.timedelta(days=365)          # 一年前起算
    not_after = not_before + dt.timedelta(days=730)    # 两年

    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, DOMAINS[0]),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Local Car Unit Proxy"),
    ])

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(inter.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(d) for d in DOMAINS]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=True, data_encipherment=False,
                key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()),
                       critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(inter.public_key()),
            critical=False,
        )
    )

    leaf = builder.sign(private_key=inter_key, algorithm=hashes.SHA384())

    chain_path = os.path.join(OUT, "chain.pem")
    with open(chain_path, "wb") as f:
        f.write(leaf.public_bytes(serialization.Encoding.PEM))
        # 中间证书: AAA Certificate Services 交叉签名版
        f.write(inter.public_bytes(serialization.Encoding.PEM))
        # 追加 emSign 原签发版中间证书 + emSign Root TLS CA - G3 (由 emSign ECC Root CA - G3 交叉签名)
        # -> 给车机第二条信任路径 (emSign ECC Root CA - G3 在 Apple/Chrome/MS/Mozilla 四家根库都在)
        for extra in EXTRA_CERTS:
            p = os.path.join(CERTS, extra)
            if os.path.exists(p):
                f.write(open(p, "rb").read())
                print(f"[OK] 追加链证书 {extra}")
            else:
                print(f"[WARN] 缺少 {extra}, 跳过")

    key_path = os.path.join(OUT, "leaf.key.pem")
    with open(key_path, "wb") as f:
        f.write(leaf_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))

    print(f"[OK] leaf cert serial={leaf.serial_number:x}")
    print(f"     SAN = {', '.join(DOMAINS)}")
    print(f"     notBefore = {not_before.isoformat()}")
    print(f"     notAfter  = {not_after.isoformat()}")
    print(f"     签名算法 = {leaf.signature_algorithm_oid._name}")
    print(f"     -> {chain_path}")
    print(f"     -> {key_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
