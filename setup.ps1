<#
.SYNOPSIS
    车机第三方 APK 注入方案 —— 环境准备脚本 (Windows 10/11)

.DESCRIPTION
    -Hosts     备份并劫持 hosts (两个商店域名 -> 热点网关 IP)
    -Firewall  放行 443 入站 (需要管理员)
    -Restore   从备份还原 hosts
    -All       依次执行 Hosts + Firewall
    -Check     只做体检, 不修改任何东西

.EXAMPLE
    .\setup.ps1 -Hosts
    .\setup.ps1 -All
    .\setup.ps1 -Restore
#>
[CmdletBinding()]
param(
    [switch]$Hosts,
    [switch]$Firewall,
    [switch]$Restore,
    [switch]$All,
    [switch]$Check
)

$ErrorActionPreference = "Stop"

$HostsPath   = "$env:SystemRoot\System32\drivers\etc\hosts"
$BackupPath  = "$HostsPath.workbuddy.bak"
$GatewayIP   = "192.168.137.1"
$Domains     = @("prod-r-platform.z-onesoft.com",
                 "prod-dp-public-es33.oss-cn-shanghai.aliyuncs.com")
$BeginMarker = "# ==== WorkBuddy car-unit proxy (own-vehicle APK test) ===="
$EndMarker   = "# ==== end WorkBuddy car-unit proxy ===="

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Write-Head($t) { Write-Host ""; Write-Host "=== $t ===" -ForegroundColor Cyan }

function Get-HotspotGateway {
    # 移动热点网关固定 192.168.137.1; 若被改过, 找带 192.168.137.* 的网卡
    $hit = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
           Where-Object { $_.IPAddress -eq $GatewayIP }
    if ($hit) { return $hit.InterfaceAlias }
    return $null
}

function Set-HijackHosts {
    Write-Head "hosts 劫持"
    if (-not (Test-Admin)) {
        Write-Host "[FAIL] 需要管理员权限。请以管理员身份运行 PowerShell。" -ForegroundColor Red
        return $false
    }
    if (-not (Test-Path $HostsPath)) {
        Write-Host "[FAIL] 找不到 $HostsPath" -ForegroundColor Red
        return $false
    }

    # 1) 备份 (只在第一次备份, 避免覆盖掉用户自己的原始备份)
    if (-not (Test-Path $BackupPath)) {
        Copy-Item $HostsPath $BackupPath -Force
        Write-Host "[OK] 已备份 hosts -> $BackupPath" -ForegroundColor Green
    } else {
        Write-Host "[SKIP] 备份已存在: $BackupPath" -ForegroundColor Yellow
    }

    # 2) 移除本工具旧的区块 (如果有)
    $lines = Get-Content $HostsPath
    $out = New-Object System.Collections.Generic.List[string]
    $skip = $false
    foreach ($l in $lines) {
        if ($l -match [regex]::Escape($BeginMarker)) { $skip = $true; continue }
        if ($l -match [regex]::Escape($EndMarker))   { $skip = $false; continue }
        if (-not $skip) { $out.Add($l) }
    }

    # 3) 检查是否有指向真实 IP 的同名旧记录 (那等于"不劫持"), 注释掉
    $fixed = New-Object System.Collections.Generic.List[string]
    foreach ($l in $out) {
        $isTarget = $false
        foreach ($d in $Domains) {
            if ($l -match "^\s*\S+\s+.*\b$([regex]::Escape($d))\b") { $isTarget = $true; break }
        }
        if ($isTarget -and $l -notmatch "^\s*#") {
            $fixed.Add("# [WorkBuddy disabled] $l")
            Write-Host "[WARN] 已注释指向其它地址的旧记录: $($l.Trim())" -ForegroundColor Yellow
        } else {
            $fixed.Add($l)
        }
    }

    # 4) 写入新的区块
    $block = @()
    $block += ""
    $block += $BeginMarker
    $block += "# BACKUP: hosts.workbuddy.bak   REMOVE: .\setup.ps1 -Restore"
    foreach ($d in $Domains) { $block += "$GatewayIP $d" }
    $block += $EndMarker
    $fixed.AddRange($block)

    Set-Content -Path $HostsPath -Value $fixed -Encoding ASCII
    Write-Host "[OK] 已写入 $Domains.Count 条劫持记录 -> $GatewayIP" -ForegroundColor Green
    Write-Host ""
    Write-Host "hosts 尾部:" -ForegroundColor DarkGray
    Get-Content $HostsPath | Select-Object -Last 6 | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray }
    return $true
}

function Restore-Hosts {
    Write-Head "还原 hosts"
    if (-not (Test-Admin)) {
        Write-Host "[FAIL] 需要管理员权限。" -ForegroundColor Red
        return $false
    }
    if (-not (Test-Path $BackupPath)) {
        Write-Host "[FAIL] 找不到备份 $BackupPath" -ForegroundColor Red
        return $false
    }
    Copy-Item $BackupPath $HostsPath -Force
    Write-Host "[OK] 已从备份还原 hosts" -ForegroundColor Green
    return $true
}

function Set-FirewallRule {
    Write-Head "防火墙 443"
    if (-not (Test-Admin)) {
        Write-Host "[FAIL] 需要管理员权限。" -ForegroundColor Red
        return $false
    }
    $name = "CarAPKInjector 443"
    $existing = Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "[SKIP] 规则已存在: $name" -ForegroundColor Yellow
        return $true
    }
    New-NetFirewallRule -DisplayName $name -Direction Inbound -LocalPort 443 `
        -Protocol TCP -Action Allow -Profile Any | Out-Null
    Write-Host "[OK] 已添加入站规则: $name" -ForegroundColor Green
    return $true
}

function Test-Environment {
    Write-Head "环境体检"
    $ok = $true

    # Python
    $py = Get-Command python -ErrorAction SilentlyContinue
    if ($py) {
        $ver = (& python --version 2>&1) -join ""
        Write-Host "[OK] Python: $ver" -ForegroundColor Green
    } else {
        Write-Host "[FAIL] 未找到 python, 请先安装 (勾选 Add to PATH)" -ForegroundColor Red
        $ok = $false
    }

    # 依赖
    if ($py) {
        $r = & python -c "import cryptography,brotli;print('OK')" 2>&1
        if ($r -match "OK") {
            Write-Host "[OK] 依赖 cryptography / brotli" -ForegroundColor Green
        } else {
            Write-Host "[WARN] 依赖缺失, 请执行: python -m pip install cryptography brotli" -ForegroundColor Yellow
            $ok = $false
        }
    }

    # 证书
    foreach ($f in @("pki\chain.pem", "pki\leaf.key.pem")) {
        if (Test-Path $f) { Write-Host "[OK] 证书存在: $f" -ForegroundColor Green }
        else { Write-Host "[FAIL] 缺少 $f" -ForegroundColor Red; $ok = $false }
    }

    # 证书有效期
    if (Test-Path "pki\chain.pem") {
        $exp = & openssl x509 -in pki\chain.pem -noout -enddate 2>$null
        if ($exp) { Write-Host "[INFO] 叶子证书到期: $exp" -ForegroundColor DarkGray }
    }

    # 规则与 APK
    if (Test-Path "store_rules.json") {
        $rj = Get-Content store_rules.json -Raw -Encoding UTF8 | ConvertFrom-Json
        Write-Host "[OK] 规则: serve $($rj.serve.Count) 条 / patch $($rj.patch.Count) 条" -ForegroundColor Green
        $apk = $rj.apk_path
        if ($apk -and (Test-Path $apk)) {
            $sz = (Get-Item $apk).Length
            Write-Host "[OK] APK: $apk ($sz bytes)" -ForegroundColor Green
            $expSize = $rj.apk_size
            if ($expSize -and $expSize -ne $sz) {
                Write-Host "[WARN] apk_size($expSize) 与实际($sz) 不一致, 请更新 store_rules.json" -ForegroundColor Yellow
                $ok = $false
            }
        } else {
            Write-Host "[FAIL] APK 不存在: $apk" -ForegroundColor Red
            $ok = $false
        }
    }

    # 热点网关
    $alias = Get-HotspotGateway
    if ($alias) {
        Write-Host "[OK] 热点网关 $GatewayIP 存在于网卡 '$alias'" -ForegroundColor Green
    } else {
        Write-Host "[WARN] 未找到 $GatewayIP —— 移动热点可能没开。先开热点再启动代理。" -ForegroundColor Yellow
    }

    # hosts
    if (Test-Path $HostsPath) {
        $h = Get-Content $HostsPath
        foreach ($d in $Domains) {
            $hit = $h | Where-Object { $_ -match "^\s*192\.168\.137\.1\s+.*\b$([regex]::Escape($d))\b" }
            if ($hit) { Write-Host "[OK] hosts 已劫持: $d" -ForegroundColor Green }
            else { Write-Host "[WARN] hosts 未劫持: $d (执行 .\setup.ps1 -Hosts)" -ForegroundColor Yellow }
        }
    }

    # 端口
    $listen = Get-NetTCPConnection -LocalPort 443 -State Listen -ErrorAction SilentlyContinue
    if ($listen) {
        Write-Host "[INFO] 443 已被占用 (代理可能已在运行)" -ForegroundColor DarkGray
    } else {
        Write-Host "[OK] 443 空闲" -ForegroundColor Green
    }

    Write-Host ""
    if ($ok) { Write-Host "体检通过" -ForegroundColor Green } else { Write-Host "体检发现问题, 见上方 WARN/FAIL" -ForegroundColor Yellow }
    return $ok
}

# ------------------------------------------------------------------ 主流程
Write-Host ""
Write-Host "  车机第三方 APK 注入 —— 环境准备" -ForegroundColor Green
Write-Host "  ---------------------------" -ForegroundColor Green

if ($Check) {
    Test-Environment | Out-Null
    exit 0
}
if ($Restore) {
    Restore-Hosts | Out-Null
    exit 0
}
if ($All) {
    Set-HijackHosts | Out-Null
    Set-FirewallRule | Out-Null
    Test-Environment | Out-Null
    exit 0
}
if ($Hosts) {
    Set-HijackHosts | Out-Null
    exit 0
}
if ($Firewall) {
    Set-FirewallRule | Out-Null
    exit 0
}

Write-Host ""
Write-Host "请指定操作:" -ForegroundColor Yellow
Write-Host "  .\setup.ps1 -Hosts      备份并劫持 hosts"
Write-Host "  .\setup.ps1 -Firewall   放行 443 入站"
Write-Host "  .\setup.ps1 -All        两者都做 + 体检"
Write-Host "  .\setup.ps1 -Restore    还原 hosts"
Write-Host "  .\setup.ps1 -Check      只体检, 不修改"
exit 1
