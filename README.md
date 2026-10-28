# 车机应用商店 · 第三方 APK 注入

在**自己的车机**上，通过笔记本开热点做网关，拦截应用商店的详情接口与 APK 下载，
把商店里的某个应用替换成你自己的 APK。

> **使用边界**：仅限本人拥有的设备与车辆，在自建热点网络内完成。
> 所用中间证书已被 Chrome / Firefox / Apple / Microsoft 于 2026-10 移除并吊销，
> 现代系统无法被此链欺骗；有效性只针对未更新信任库的旧车机。
> 请勿用于他人设备，仅供学习研究，24小时内删除。

---

## 快速开始

```powershell
# 1. 依赖
python -m pip install cryptography brotli

# 2. 改 hosts + 开防火墙 (管理员 PowerShell)
.\setup.ps1 -All

# 3. 把你的 APK 放到 apk\ 目录, 按 docs\02 的第 4 节改 store_rules.json

# 4. 开 Windows 移动热点, 车机连上

# 5. 起代理 (保持窗口), 另开窗口自检
python proxy_server.py
python selftest.py          # 期望 61 通过 / 0 失败
```

然后在车机上：**设置 → 应用管理 → 应用商店 → 清除数据**，
再进「最美天气」详情页 → 应该显示你填的名字和体积 → 点安装。

完整步骤见 **[docs/02-Windows10全新安装操作指南.md](docs/02-Windows10全新安装操作指南.md)**。

---

## 文档

| 文档 | 内容 |
|---|---|
| [docs/01-实现原理.md](docs/01-实现原理.md) | DNS 劫持 / TLS 冒充 / 内容替换 三层原理，证书链选择依据，所有踩过的坑 |
| [docs/02-Windows10全新安装操作指南.md](docs/02-Windows10全新安装操作指南.md) | 全新 Windows 10 从零到装完，含排查对照表 |

---

## 目录结构

```
car-apk-injector/
├── proxy_server.py        代理服务端 (443, 单 SSLContext 多 SAN)
├── selftest.py            自检脚本 (61 项)
├── store_rules.json       规则: serve 1 条 + patch 1 条  ← 换 APK 改这里
├── setup.ps1              环境准备 (hosts / 防火墙 / 还原 / 体检)
├── pki/
│   ├── chain.pem          叶子 + 3 张中间件 (覆盖 3 个信任库)
│   └── leaf.key.pem       叶子私钥 (PKCS8)
├── certs/
│   ├── recover_keys.py    弱私钥还原 (d = 1..2^20, 雅可比 P-384)
│   ├── sign_leaf.py       叶子证书签发 (有效期从一年前起算两年)
│   ├── verify_jsse.py     JSSE 兼容性验证 (3/3)
│   ├── e2e_patch_test.py  patch 端到端验证
│   ├── JsseTlsClient.java JSSE 握手探针
│   ├── jsse_matrix_test.py 链组合矩阵
│   ├── keys/              还原出的 8 个中间证书私钥
│   ├── inter/             16 张中间证书副本
│   ├── fixtures/          车机真实响应固件 (chunked)
│   └── root_*.pem         4 张根证书
├── apk/                   放你要安装的 APK
└── docs/                  三份说明文档
```

---

## 工作原理一句话

```
车机 ──Wi-Fi──> 笔记本热点 192.168.137.1
                  ├─ hosts 劫持 + ICS DNS  → 商店域名解析到笔记本
                  ├─ 还原 eMudhra 弱私钥中间证书 → 签出车机信任的叶子证书
                  └─ 改写详情 JSON + 拦截下载路径直投你的 APK
```

---

## 换 APK 的三步

1. 把新 APK 放进 `apk/`
2. 改 `store_rules.json`：
   - `apk_path` / `serve[0].file` → 新 APK 路径
   - `apk_size` → 新 APK 字节数
   - `patch[0].set` → 新应用名 / 包名 / `appActualSize`(字节//1024) / `appDisplaySize`(字节//1048576+"M")
3. 重启代理

体积换算：

```powershell
python -c "import os;s=os.path.getsize(r'apk\myapp.apk');print(s//1024, s//1048576)"
```

---

## 排障速查

| 现象 | 看哪 |
|---|---|
| 车机报「网络异常」 | `selftest.py` 的 **[8] 响应完整性** 要 PASS |
| 商店一直转圈 | 代理窗口的 `[ERROR] 转发失败: The read operation timed out` |
| 详情页还是官方信息 | 代理窗口的 `[WARN] 响应不是 JSON` + `body前32字节=` |
| 详情页对但装到官方 app | 有没有 `[serve] 规则命中` 行 |
| 详情页改了但页面没变 | 车机 **清除商店数据** |
| TLS 握手失败 | `python certs\verify_jsse.py` 看哪个根不可用 |

更详细的排查见操作指南第 10 节。

---

## 还原

```powershell
.\setup.ps1 -Restore      # 还原 hosts
```

代理窗口 `Ctrl+C` 停止。
