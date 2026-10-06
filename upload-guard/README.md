# Upload Guard（上传行为守卫） v0.2.0

检测 ZCode Agent 工具调用中的**异常（未授权）数据外发行为**，在屏幕**右上角弹窗**提示，并允许用户**一键截获**。
无界面/弹窗不可用时，自动回退到 **ZCode 原生 PreToolUse 确认**（`permissionDecision: ask`）。

## 工作原理

插件注册一个 `PreToolUse` 钩子（PowerShell 实现，无第三方依赖），在工具执行**之前**拦截检查：

`Bash | PowerShell | Write | Edit | ApplyPatch | NotebookEdit | WebFetch | WebSearch | web_search | mcp__.*`

1. **提取外发目标**
   - URL 主机名（大小写不敏感，IPv6 归一化，如 `[::1]` → `::1`）
   - UNC 网络路径（`\\host\share`）
   - 网络命令特征（curl / wget / iwr / BITS / certutil / ssh / scp / socat / openssl s_client / git push / 包发布 / 云存储（aws·gsutil·az·gcloud·rclone）/ 容器推送 / DNS 查询 / 一次性脚本联网 / `-EncodedCommand` / `iex`+下载 / 数据库导出 等）
2. **白名单比对**：目标命中 `hosts` 或命令命中 `commands` → 放行并记录日志。
3. **弹窗询问**：存在未授权目标时，右上角置顶警告窗（默认倒计时 30 秒）：
   - **截获并阻止**（默认，Enter/Esc/超时/关窗均触发）
   - **放行本次**
   - **放行并加入白名单**
4. **原生回退**：弹窗创建失败（无桌面/无 WinForms）时，输出 `permissionDecision: ask`，交给 ZCode 自己的确认流程。
5. **审计日志**：每次判定追加到 `%USERPROFILE%\.zcode\upload-guard\log.jsonl`。

## 退出码与输出约定（ZCode）

| 场景 | 行为 |
|---|---|
| 放行 | 无 stdout，`exit 0` |
| 截获 | 原因写 stderr，`exit 2` |
| 原生确认回退 | stdout 输出严格 JSON，`exit 0` |
| 钩子内部错误 | 记日志后 `exit 0`（fail-open） |

原生 JSON 形状（与 ZCode `HookJSONOutput` schema 对齐）：

```json
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"..."}}
```

## 白名单

`%USERPROFILE%\.zcode\upload-guard\whitelist.json`：

```json
{
  "hosts": ["localhost", "127.0.0.1", "::1", "*.local", "company.com", "*.trusted.example", "\\\\fileserver"],
  "commands": ["^git\\s+push(\\s+\\S+){0,3}$"]
}
```

- `hosts`：精确主机名 / 显式通配 `*.example.com`（同时匹配 `example.com`）/ UNC 主机 `\\fileserver`。
  **不再隐式放行子域**：填 `company.com` 不会放行 `evil.company.com`，需要子域请写 `*.company.com`。
- `commands`：**整条命令**的正则（自动加 `^(?:…)$` 锚定），只在「网络特征命中但解析不出目标」时生效；
  一旦解析出真实外发目标（URL/UNC/git 远端），仍按 `hosts` 判定，因此 `git push && curl evil.com` 不会被放行。
- `(未知外发目标)` 无法加入白名单（避免一键放行所有无法解析的外发）。

## 对 Write/Edit 的口径

- 目的路径是 UNC（写入网络共享）→ 判定为外发。
- 正文里**只有 URL** → 不拦截（避免写文档/代码误报）。
- 正文里**同时出现网络命令 + URL**（例如写入一个含 `curl https://…` 的脚本）→ 拦截。

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
因此 `inspect-upload.ps1` 顶层有 try/catch 兜底，且解析错误分支不会再抛异常。
注意：这一策略意味着「守卫失效时不会阻止外发」，安全性来自正常路径的拦截。

## 局限性（诚实声明）

- 工具层检测基于命令/参数启发式，看不到工具执行后的真实系统调用；高度混淆（base64 拼接 URL、分片写入）仍可能漏检。
- 模型 API 请求由 ZCode 主进程直接发起，不经过工具调用，不在监控范围内。
- DNS/连通性等特征较易误报，可用 `UPLOAD_GUARD_IGNORE_SIGS` 或弹窗放行。
- 弹窗不可用时回退 `ask`；若宿主处于自动放行的权限模式，需用 `UPLOAD_GUARD_NATIVE_ASK=0` 改为直接阻止。

## 文件清单

```
upload-guard/
├── .zcode-plugin/plugin.json   插件清单
├── hooks/hooks.json            PreToolUse 钩子注册（process 类型，45s 超时）
├── hooks/inspect-upload.ps1    检测 + 弹窗 + 拦截（UTF-8 with BOM）
├── commands/upload-guard.md    /upload-guard 管理命令
├── tests/smoke-test.ps1        隔离环境冒烟测试（21 例）
├── tests/e2e-button-test.ps1   弹窗按钮端到端自测（PerformClick 注入）
└── README.md
```

注意：`inspect-upload.ps1` 含中文，必须保存为 **UTF-8 with BOM**，否则 Windows PowerShell 5.1 会按 ANSI 误读导致解析错误。
编辑该文件后请务必确认 BOM 仍在（例如 `Get-Content -Encoding Byte -TotalCount 3`）。

## v0.2.0 相对 v0.1.0 的变更

修复：

1. **解析错误崩溃**：`Substring(0, Min(120, raw.Length))` 作用于压缩空白后的字符串，长度不一致会抛异常（退出码 1）。现按压缩后长度裁剪，fail-open 真正生效。
2. **URL 大小写绕过**：`HTTPS://` / `HTTP://` 不再逃过 URL 提取（改用 IgnoreCase，并新增 `-EncodedCommand`、`iex`+下载等绕过特征）。
3. **IPv6 误判**：`[::1]` 归一化为 `::1`，本机回环不再被当作外发。
4. **Write/Edit 正文误报**：正文只有 URL 不再弹窗，改为「网络命令 + URL 同时出现」。
5. **白名单语义收紧**：移除隐式子域后缀匹配，必须显式 `*.`。
6. **`.git` 配置读取**：`git push` 等无 URL 命令会尝试读取 `.git/config` 解析真实远端主机。
7. **命令白名单**：新增 `commands` 字段，解决 `git push` 每次都弹窗的问题。

新增探针：python/node/php 联网、openssl s_client、socat、rclone/aws/gsutil/az/gcloud、docker/podman push、DNS 查询、`-EncodedCommand`、编码执行+下载、数据库导出、网络文件写等；
并接入 ZCode 原生 `ask` 回退。
