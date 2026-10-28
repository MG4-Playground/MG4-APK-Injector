把你的 APK 放在这个目录 (例如 myapp.apk),
然后按 docs/02-Windows10全新安装操作指南.md 第 4 节改 store_rules.json。
store_rules.json 里 apk_path 与 serve[0].file 写成相对路径 (如 apk/myapp.apk),
相对路径以 store_rules.json 所在目录为基准, 整个包可随意搬走。
