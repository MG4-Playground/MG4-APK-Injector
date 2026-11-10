把你的 APK 放在这个目录 (例如 myapp.apk),
然后按 docs/02-Windows10全新安装操作指南.md 第 4 节改 store_rules.json。
store_rules.json 里 apk_path 与全部 serve[].file 都写成相对路径 (如 apk/myapp.apk) ——
两条 serve 规则分别对应旧 OSS 与新 z-onesoft CDN 下载域名, 必须都改,
相对路径以 store_rules.json 所在目录为基准, 整个包可随意搬走。
