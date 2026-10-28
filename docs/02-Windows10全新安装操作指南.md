# 在一台全新的 Windows 10 上完成安装

> 从零开始，把自己的 APK 装到车机应用商店里。
> 全程约 20 分钟，含编译证书（如需）。
>
> **前置**：车机支持连接 Wi-Fi 热点；你有 Windows 10 管理员权限的笔记本。

---

## 0. 整体流程速览

```
① 装环境 (Python + 依赖)
② 放证书 + 放你的 APK
③ 改规则文件 (store_rules.json) ← 换 APK 只改这一步
④ 改 hosts (劫持两个域名)
⑤ 开防火墙 443 端口
⑥ 开移动热点, 车机连上
⑦ 起代理 → 跑自检 → 上车机操作
```

**改 APK 只需要重做 ③ 和 ⑦**，其余步骤做完一次就不用再管。

---

## 1. 安装 Python 与依赖

### 1.1 装 Python

- 打开 <https://www.python.org/downloads/windows/>
- 下载 **Windows installer (64-bit)**
- 安装时**务必勾选 `Add python.exe to PATH`**（第一页底部那个复选框）

验证（打开 PowerShell）：

```powershell
python --version
```

应输出 `Python 3.10.x` 或更高。如果提示"找不到 python"，
说明 PATH 没加上 —— 重装并勾选那个选项，或手动加
`C:\Users\<你的用户名>\AppData\Local\Programs\Python\Python3xx\Scripts`。

### 1.2 装依赖

```powershell
cd <解压目录>\car-apk-injector
python -m pip install cryptography brotli
```

验证：

```powershell
python -c "import cryptography, brotli; print('deps OK')"
```

---

## 2. 放证书与你的 APK

### 2.1 证书（已经放好了）

`pki/chain.pem` 和 `pki/leaf.key.pem` 已随包提供。

> **注意有效期**：叶子证书有效期是 **签发当天往前一年、往后一年**。
> 如果你隔了很久才用，需要重新签发（见第 3 节），否则车机会因证书过期而拒绝连接。

### 2.2 放你的 APK

把你的 APK 放进 `apk/` 目录，例如：

```
car-apk-injector/apk/myapp.apk
```

> 包里自带的 `apk/target.apk` 是一个可用的示例（德赛西威无线ADB按钮），
> 装完就能验证整条链路通不通。

---

## 3. （可选）重新签发证书

**如果你刚拿到包就用，跳过这节。**
只有以下情况需要重签：证书已过期，或你换了目标域名。

```powershell
cd <解压目录>\car-apk-injector
python certs\sign_leaf.py
```

输出示例：

```
[OK] 中间证书 CN=EM OV TLS CA - G3C,O=eMudhra Inc,C=US
     私钥与公钥坐标一致 (d 已正确还原)
[OK] leaf cert serial=...
     SAN = prod-r-platform.z-onesoft.com, prod-dp-public-es33.oss-cn-shanghai.aliyuncs.com
     notBefore = ...        ← 一年前
     notAfter  = ...        ← 两年后
```

> `sign_leaf.py` 会自动从 `certs/chains.zip` 提取所需中间证书，**无需手工准备**。

---

## 4. 改规则文件（换 APK 只改这里）

打开 `store_rules.json`，改 `serve` 和 `patch` 里的路径与字段：

```json
{
  "apk_path": "C:/绝对路径/car-apk-injector/apk/myapp.apk",
  "apk_size": 157605849,
  "serve": [
    {
      "host": "prod-dp-public-es33.oss-cn-shanghai.aliyuncs.com",
      "path_prefix": "/ecology/",
      "file": "C:/绝对路径/car-apk-injector/apk/myapp.apk"
    }
  ],
  "patch": [
    {
      "host": "prod-r-platform.z-onesoft.com",
      "method": "POST",
      "path_prefix": "/eco/ippf/appMarket/vehicle/app/detail",
      "set": {
        "data.appName": "你的应用名",
        "data.appPackage": "com.your.package",
        "data.appActualSize": "153911",
        "data.appDisplaySize": "150M"
      }
    }
  ]
}
```

### 4.1 算体积

```powershell
python -c "import os;s=os.path.getsize(r'apk\myapp.apk');print(s, '->', s//1024, 'KB,', s//1048576, 'M')"
```

把输出的两个数字填进 `appActualSize`（纯数字字符串）和 `appDisplaySize`（带 M）。

### 4.2 取包名和应用名

```powershell
python -m pip install androguard
python -c "from androguard.core.apk import APK; a=APK(r'apk\myapp.apk'); print(a.get_package(), '|', a.get_app_name())"
```

把包名填进 `data.appPackage`，应用名填进 `data.appName`。

> **如果你的应用名带中文**，请把 `store_rules.json` 保存为 **UTF-8** 编码
> （VS Code 右下角点 "UTF-8" 即可切换；记事本另存为时选 "UTF-8"）。
> 编码错了车机上会显示乱码。

---

## 5. 改 hosts（劫持域名）

**必须以管理员身份运行 PowerShell**（右键 → "以管理员身份运行"）。

```powershell
cd <解压目录>\car-apk-injector
.\setup.ps1 -Hosts
```

它会自动：
1. 备份 `C:\Windows\System32\drivers\etc\hosts` → `hosts.workbuddy.bak`
2. 写入两条劫持记录
3. 显示结果

手动确认：

```powershell
Get-Content C:\Windows\System32\drivers\etc\hosts | Select-Object -Last 6
```

应看到：

```
# ==== WorkBuddy car-unit proxy (own-vehicle APK test) ====
# BACKUP: hosts.workbuddy.bak
192.168.137.1 prod-r-platform.z-onesoft.com
192.168.137.1 prod-dp-public-es33.oss-cn-shanghai.aliyuncs.com
# ==== end WorkBuddy car-unit proxy ====
```

### 5.1 如果你的机器上已有旧的劫持记录

Windows 的 hosts **同一域名多行时行为不确定**。请确认没有其他行也指向这两个域名：

```powershell
Select-String -Path C:\Windows\System32\drivers\etc\hosts -Pattern "z-onesoft|aliyuncs"
```

若看到指向**真实 IP** 的旧记录（例如 `58.144.228.12 prod-r-platform.z-onesoft.com`），
那是"不劫持"的效果，会让车机绕过代理 —— **必须注释掉或删除**。

---

## 6. 开防火墙 443 端口

管理员 PowerShell：

```powershell
cd <解压目录>\car-apk-injector
.\setup.ps1 -Firewall
```

等价于：

```powershell
New-NetFirewallRule -DisplayName "CarAPKInjector 443" -Direction Inbound -LocalPort 443 -Protocol TCP -Action Allow -Profile Private
```

> 首次运行时 Windows 会弹"防火墙阻止"提示，选**允许访问**即可；
> 但用命令加规则更保险（弹窗只针对私有/公用网络的特定程序）。

---

## 7. 开移动热点并让车机连上

1. Windows **设置 → 网络和 Internet → 移动热点**
2. 打开开关，记下热点名称和密码
3. 车机 **设置 → Wi-Fi** → 找到该热点 → 输入密码 → 连接

### 7.1 记下网关 IP

Windows 移动热点的网关固定是 `192.168.137.1`（除非你改过 ICS 设置）。确认一下：

```powershell
Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -like "*本地连接*" } | Select-Object InterfaceAlias,IPAddress
```

> 如果你用的是**共享网络**给另一台机器做网关（不是移动热点），
> 网关 IP 可能不同，需要同时改三处：
> `store_rules.json` 无关，但 `proxy_server.py` 顶部的 `GATEWAY_IP`、
> hosts 里的两行、以及防火墙规则。

### 7.2 验证 DNS 劫持生效（**关键**）

在车机连接热点后，于笔记本上执行：

```powershell
python -c "import socket,struct; qn=b''.join(bytes([len(p)])+p.encode() for p in 'prod-r-platform.z-onesoft.com'.split('.'))+b'\x00'; pk=struct.pack('>HHHHHH',0x1234,0x0100,1,0,0,0)+qn+struct.pack('>HH',1,1); s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(4); s.sendto(pk,('192.168.137.1',53)); d,_=s.recvfrom(1024); print('DNS 应答', len(d), '字节')"
```

**只要收到应答就说明 ICS DNS 代理在正常工作**（能应答即表示它接管了查询）。
若超时，说明热点 DNS 没接管查询 —— 见第 10 节排查。

---

## 8. 起代理 + 自检

```powershell
cd <解压目录>\car-apk-injector
python proxy_server.py
```

**保持这个窗口开着**。另开一个窗口跑自检：

```powershell
python selftest.py
```

期望：

```
结果: 61 通过 / 0 失败  (共 61 项)
```

再跑证书兼容性验证（需要 JDK）：

```powershell
# 没有 JDK 会跳过, 不影响主流程
python certs\verify_jsse.py
```

期望：

```
结果: 3/3 个信任库握手成功
```

> **这一步为什么重要**：它用 JDK 的 JSSE 引擎（路径构建逻辑与 Android Conscrypt 最接近）
> 分别以三个候选根 CA 作唯一信任锚做**真实 TLS 握手**。
> 3/3 通过基本可保证车机握手成功；不足 3 个就要换证书（见第 10 节）。

---

## 9. 车机上怎么点

### 步骤 1 — 确认连接
车机状态栏显示已连接热点。

### 步骤 2 — 清缓存（**很重要**）
车机 **设置 → 应用管理 → 应用商店 → 清除数据**。
不清的话车机会用缓存的旧详情页，改写看不到效果。

### 步骤 3 — 进详情页
车机桌面 → **应用商店 / 应用市场** → 搜 **最美天气** → 点进详情页（先别点下载）。

此时详情页应该显示：
- 名称：**你填的应用名**
- 体积：**你填的体积**（如 `150M`）

### 步骤 4 — 安装
点 **下载 / 安装**。车机下载器会请求
`/ecology/ecofile-<hash>.apk`，被代理拦下换成你的 APK。

### 步骤 5 — 确认
回到车机桌面 / 应用列表，找到你的应用，能正常启动即成功。

---

## 10. 排查对照表

| 现象 | 看哪行日志 / 怎么查 | 原因 | 怎么修 |
|---|---|---|---|
| 应用商店提示**网络异常**，日志里显示 `[pass] 原样转发 (1739 bytes)` 却收不到内容 | 代理窗口 | 代理只记日志没真发出响应 | 确认跑的是最新代码；`python selftest.py` 的 **[8] 响应完整性** 要 PASS |
| 应用商店**一直转圈**，日志有 `[ERROR] 转发失败: The read operation timed out` | 代理窗口 | 上游 keep-alive，代理读到 EOF 一直等 | 确认代码最新并重启代理 |
| 详情页还是**官方信息**，日志有 `[WARN] 响应不是 JSON` | 看日志里 `body前32字节=` | 上游用 chunked 编码，body 是 `68d\r\n{...}` | 确认代码含 `decode_chunked()`；`selftest.py` 的 **[10] 真实 chunked 响应回归** 要 PASS |
| 详情页还是官方信息，但日志**没有** `[WARN]` | — | serve 规则路径没命中 | 看 `[pass] 原样转发` 那行的实际路径，加进 `store_rules.json` 的 `path_prefix` |
| 详情页改对了但**装上还是官方 app** | 有没有 `[serve] 规则命中` | 下载路径没匹配上 | 同上；车机实际路径是 `/ecology/ecofile-<hash>.apk` |
| 有 `[patch] 改写成功` 但页面没变 | — | 车机缓存 | 车机 **设置 → 应用管理 → 应用商店 → 清除数据**，重进详情页 |
| `[ERROR] TLS 握手失败` | 代理窗口 | 车机不认这张叶子证书 | 跑 `certs\verify_jsse.py` 看哪个根不可用；换另一张中间证书重签（见 10.1） |
| 车机**连不上热点** | — | 热点没开 / 车机没连 | 重新开热点，让车机连 |
| 车机连上了但商店打不开 | 第 7.2 步的 DNS 验证 | ICS DNS 没接管查询 | 见 10.2 |
| `Address already in use` | — | 443 被占 | `netstat -ano | findstr :443` 找占用进程结束掉 |
| 代理报 `转发失败: Connection reset` | — | 上游断开 | 重试；连续失败就重启代理 |

### 10.1 换一张中间证书

包内已还原全部 8 个中间证书的私钥（`certs/keys/`）。改
`certs/sign_leaf.py` 里的：

```python
INTER_SLUG = "EM_OV_TLS_CA___G3C__aaa"
```

换成别的（如 `"EM_DV_TLS_CA___G3B__aaa"`、`"EM_EV_TLS_CA___G3C__aaa"`），
然后：

```powershell
python certs\sign_leaf.py
python certs\verify_jsse.py
```

### 10.2 ICS DNS 不接管查询时

车机连上热点后，若第 7.2 步 DNS 查询超时：

**方案 A（推荐）**：在车机 Wi-Fi 设置里把 **DNS 服务器手动填成 `192.168.137.1`**，
然后让车机重新连一次热点。

**方案 B**：确认热点是"移动热点"而不是"共享网络"。移动热点才会给客户端
下发 `192.168.137.1` 作为 DNS。

**方案 C**：改用网线共享给另一台机器（网关 IP 会变，需同步改
`proxy_server.py` 的 `GATEWAY_IP` 和 hosts 两行）。

---

## 11. 结束与还原

### 停代理
代理窗口按 `Ctrl+C`。

### 还原 hosts
管理员 PowerShell：

```powershell
cd <解压目录>\car-apk-injector
.\setup.ps1 -Restore
```

或手动：

```powershell
Copy-Item "$env:SystemRoot\System32\drivers\etc\hosts.workbuddy.bak" `
          "$env:SystemRoot\System32\drivers\etc\hosts" -Force
```

### 删防火墙规则（可选）

```powershell
Remove-NetFirewallRule -DisplayName "CarAPKInjector 443"
```

---

## 12. 常见问题

**Q：车机详情页一直显示官方信息，改了 store_rules.json 没生效？**
A：① 确认改了之后**重启了代理**（规则在启动时读入）；② 车机**清除商店数据**；
③ 看日志有没有 `[patch] 改写成功`。

**Q：可以一次装多个不同的 APK 吗？**
A：可以，但每次只能替换"同一个"详情页。要装不同的 app，就改
`store_rules.json` 里的 `set` 字段和 `apk` 路径，重启代理，
然后在车机上重新进一次详情页。

**Q：车机上会不会弹"证书错误"？**
A：不会。代理出示的证书链能被旧车机的系统信任库接受；
`certs/verify_jsse.py` 就是用来提前确认这件事的。

**Q：会不会影响车机其他功能（导航、电话）？**
A：只劫持了两个商店域名（商店详情接口 + 资源下载），
其余请求一律原样转发。

**Q：证书能给别人用吗？**
A：**不建议也不应该**。这些中间证书已被全球根库移除，
只对未更新信任库的旧车机有效；请仅用于你自己的车辆。

---

## 13. 命令速查

```powershell
# 管理员 PowerShell, cd 到 car-apk-injector 目录

.\setup.ps1 -Hosts        # 备份并劫持 hosts
.\setup.ps1 -Firewall     # 开 443 防火墙
.\setup.ps1 -Restore      # 还原 hosts

python proxy_server.py    # 起代理 (前台, 保持窗口)
python selftest.py        # 自检 (期望 61/61)
python certs\verify_jsse.py   # 证书兼容性 (期望 3/3)
python certs\sign_leaf.py     # 重新签发叶子证书
```
