# ============================================================
# Upload Guard - PreToolUse hook  v0.2.0  (Windows PowerShell 5.1+)
# 检测 Agent 工具调用中的异常（未授权）数据外发行为。
#
# 判定流程:
#   1. 提取外发目标: URL 主机 / UNC 网络路径 / 网络命令特征
#   2. 白名单比对 (hosts + commands)，未授权 => 右上角弹窗
#   3. 弹窗不可用 => 回退 ZCode 原生确认 (permissionDecision=ask)
#   4. 超时/关窗 => 失败安全截获 (deny)
#
# ZCode 钩子约定:
#   exit 0 = 放行, exit 2 = 阻止, 其它非 0 = 钩子报错
#   stdout 若为 JSON，必须是严格 schema:
#   {"hookSpecificOutput":{"hookEventName":"PreToolUse",
#     "permissionDecision":"allow|ask|deny","permissionDecisionReason":"..."}}
#   本脚本仅在「原生 ask」时向 stdout 输出该 JSON；deny 走 stderr + exit 2。
#
# 环境变量:
#   UPLOAD_GUARD_HEADLESS=1                  无界面模式
#   UPLOAD_GUARD_AUTO=allow|deny             无头模式默认决定（默认 deny）
#   UPLOAD_GUARD_DIALOG_TIMEOUT_SEC=N         弹窗倒计时秒数（默认 30）
#   UPLOAD_GUARD_NATIVE_ASK=0                禁用原生 ask 回退（回退为直接阻止）
#   UPLOAD_GUARD_IGNORE_SIGS=a,b             忽略指定特征名
# ============================================================

$ErrorActionPreference = 'Stop'
$NL = [Environment]::NewLine

$ConfigDir     = Join-Path $env:USERPROFILE '.zcode\upload-guard'
$WhitelistPath = Join-Path $ConfigDir 'whitelist.json'
$LogPath       = Join-Path $ConfigDir 'log.jsonl'
$DefaultHosts  = @('localhost', '127.0.0.1', '::1', '*.local')
$GuardVersion  = '0.2.0'

# ---------------- 规范化 ----------------

function Normalize-Host {
    param([string]$HostName)
    $t = ([string]$HostName).Trim().TrimEnd('.').ToLower()
    if (-not $t) { return '' }
    if ($t.StartsWith('[') -and $t.EndsWith(']')) { $t = $t.Substring(1, $t.Length - 2) }
    $ip = $null
    if ([System.Net.IPAddress]::TryParse($t, [ref]$ip)) { return $ip.ToString().ToLower() }
    return $t
}

function Normalize-Target {
    param([string]$Target)
    $t = ([string]$Target).Trim().ToLower()
    if (-not $t) { return '' }
    if ($t.StartsWith('\\')) {
        $h = $t.Substring(2).TrimEnd('\')
        return '\\' + (Normalize-Host $h)
    }
    return (Normalize-Host $t)
}

# ---------------- 白名单 ----------------

function Save-Whitelist {
    param([string[]]$Hosts, [string[]]$Commands)
    $obj  = [ordered]@{ hosts = @($Hosts); commands = @($Commands) }
    $json = $obj | ConvertTo-Json -Depth 4
    [System.IO.File]::WriteAllText($WhitelistPath, $json, (New-Object System.Text.UTF8Encoding($true)))
}

function Get-Whitelist {
    $hosts = $null
    $commands = $null
    try {
        if (Test-Path -LiteralPath $WhitelistPath) {
            $w = Get-Content -LiteralPath $WhitelistPath -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($w) {
                if ($w.hosts)    { $hosts    = @($w.hosts    | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ }) }
                if ($w.commands) { $commands = @($w.commands | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ }) }
            }
        }
    } catch { }
    if (-not $hosts -or $hosts.Count -eq 0) {
        $hosts = $DefaultHosts
        try {
            if (-not (Test-Path -LiteralPath $ConfigDir)) { New-Item -ItemType Directory -Force -Path $ConfigDir | Out-Null }
            Save-Whitelist -Hosts $hosts -Commands @($commands)
        } catch { }
    }
    if (-not $commands) { $commands = @() }
    return @{ hosts = @($hosts); commands = @($commands) }
}

function Test-HostWhitelisted {
    param([string]$Target, [string[]]$Hosts)
    $t = Normalize-Target $Target
    if (-not $t) { return $true }
    foreach ($p in @($Hosts)) {
        $pat = Normalize-Target $p
        if (-not $pat) { continue }
        if ($t -eq $pat) { return $true }
        if ($pat.StartsWith('*.')) {
            if ($t.EndsWith($pat.Substring(1))) { return $true }
            if ($t -eq $pat.Substring(2)) { return $true }
        }
    }
    return $false
}

function Test-CommandWhitelisted {
    param([string]$CommandText, [string[]]$Patterns)
    if (-not $CommandText) { return $false }
    foreach ($p in @($Patterns)) {
        if (-not $p) { continue }
        try {
            if ([System.Text.RegularExpressions.Regex]::IsMatch($CommandText, '^(?:' + $p + ')$', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)) { return $true }
        } catch { }
    }
    return $false
}

# ---------------- 日志 ----------------

function Write-GuardLog {
    param([string]$Tool, [string[]]$TargetList, [string]$Evidence, [string]$Decision, [string]$Reason, [string]$Session)
    try {
        if (-not (Test-Path -LiteralPath $ConfigDir)) { New-Item -ItemType Directory -Force -Path $ConfigDir | Out-Null }
        $entry = [ordered]@{
            ts       = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
            version  = $GuardVersion
            session  = $Session
            tool     = $Tool
            targets  = @($TargetList)
            evidence = $Evidence
            decision = $Decision
            reason   = $Reason
        }
        Add-Content -LiteralPath $LogPath -Value ($entry | ConvertTo-Json -Depth 4 -Compress) -Encoding UTF8
    } catch { }
}

# ---------------- 特征库 ----------------

function Get-SigMap {
    if (-not $script:SigMap) {
        $script:SigMap = [ordered]@{
            'curl'              = '\bcurl(\.exe)?\b'
            'wget'              = '\bwget(\.exe)?\b'
            'Invoke-WebRequest' = 'Invoke-WebRequest|\biwr\b'
            'Invoke-RestMethod' = 'Invoke-RestMethod|\birm\b'
            'BITS 传输'          = 'Start-BitsTransfer|\bbitsadmin\b'
            'certutil 下载'      = 'certutil(\.exe)?\s+[-/](urlcache|verifyctl|sync)'
            'ftp/sftp'          = '\b(ftp|sftp)(\.exe)?\b'
            'scp'               = '\bscp(\.exe)?\b'
            'rsync'             = '\brsync(\.exe)?\b'
            'netcat'            = '\bncat(\.exe)?\b|\bnetcat(\.exe)?\b|\bnc(\.exe)?\b'
            'telnet'            = '\btelnet(\.exe)?\b'
            'socat'             = '\bsocat(\.exe)?\b'
            'openssl 连接'       = 'openssl(\.exe)?\s+s_client'
            'ssh'               = '\bssh(\.exe)?\s'
            'ssh 隧道'           = 'ssh\s+[^\r\n]*\s-[RLD]\s'
            'PowerShell 远程'    = 'Invoke-Command[^\r\n]*-ComputerName|Enter-PSSession|New-PSSession'
            '编码执行'           = '-enc(odedcommand)?\s+[A-Za-z0-9+/=]{16,}'
            '动态执行+下载'       = '(?is)(Invoke-Expression|\biex\b)[^\r\n]{0,200}(DownloadString|DownloadFile|Invoke-WebRequest|\biwr\b|\bcurl\b|\bwget\b|FromBase64String)'
            '脚本内网络调用'      = '(?is)\b(python|python3|py|node|perl|ruby|php)\b[^\r\n]{0,400}(requests|urllib|http\.client|socket|paramiko|ftplib|boto3|oss2|aliyun|websocket|axios|Invoke-WebRequest)'
            'git push'          = 'git(\.exe)?\s+push'
            'git remote add'    = 'git(\.exe)?\s+remote\s+add'
            'git 导出'           = 'git(\.exe)?\s+(bundle|archive)'
            '包管理器发布'        = '(npm|yarn|pnpm)\s+publish|twine\s+upload|nuget\s+push|dotnet\s+nuget\s+push|cargo\s+publish|gem\s+push|mvn\s+deploy|gradle\s+publish'
            'gh 上传'            = '\bgh\s+(api|release|gist|repo|pr)\b'
            '云存储上传'          = 'aws\s+s3|aws\s+s3api|\bgsutil\b|az\s+storage|gcloud\s+storage|rclone\s+(copy|sync|move)'
            '容器推送'            = '(docker|podman)\s+push'
            'DNS 查询'           = '\b(nslookup|dig)(\.exe)?\b|Resolve-DnsName|\.Net\.Dns\]::GetHost(Addresses|Entry)'
            '邮件外发'            = 'Send-MailMessage|smtplib'
            '连通性探测'          = 'Test-NetConnection|Test-Connection[^\r\n]*-ComputerName|\btnc\b'
            '网络文件写'          = 'robocopy|xcopy|mklink|net\s+use|New-SmbMapping|subst\s+[A-Za-z]:\s+\\\\'
            '数据库导出外发'       = 'mongoexport|mongodump|mysqldump|pg_dump|sqlcmd[^\r\n]*-S\s'
        }
    }
    return $script:SigMap
}

function Get-MatchedSignatures {
    param([string]$Text)
    $out = New-Object System.Collections.Generic.List[string]
    if (-not $Text) { return @() }
    $skip = @()
    if ($env:UPLOAD_GUARD_IGNORE_SIGS) { $skip = @($env:UPLOAD_GUARD_IGNORE_SIGS -split ',' | ForEach-Object { $_.Trim() }) }
    $map = Get-SigMap
    foreach ($k in $map.Keys) {
        if ($skip -contains $k) { continue }
        try {
            if ([System.Text.RegularExpressions.Regex]::IsMatch($Text, $map[$k], [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)) { $out.Add($k) }
        } catch { }
    }
    return @($out)
}

# ---------------- 目标提取 ----------------

function Get-UrlHosts {
    param([string]$Text)
    $list = New-Object System.Collections.Generic.List[string]
    if (-not $Text) { return @() }
    $opts = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    foreach ($m in [System.Text.RegularExpressions.Regex]::Matches($Text, 'https?://[^\s"''<>\\]+', $opts)) {
        $clean = $m.Value.TrimEnd('.', ',', ')', '}', ';', "'", '"')
        $u = $null
        if ([System.Uri]::TryCreate($clean, [System.UriKind]::Absolute, [ref]$u)) {
            if ($u.Host) { $list.Add((Normalize-Host $u.Host)) }
        }
    }
    return @($list)
}

function Get-UncHosts {
    param([string]$Text, [string]$FilePath)
    $list = New-Object System.Collections.Generic.List[string]
    foreach ($src in @($Text, $FilePath)) {
        if (-not $src) { continue }
        foreach ($m in [System.Text.RegularExpressions.Regex]::Matches($src, '\\\\([A-Za-z0-9._-]+)')) {
            $h = Normalize-Host $m.Groups[1].Value
            if ($h) { $list.Add('\\' + $h) }
        }
    }
    return @($list)
}

function Resolve-GitHosts {
    param([string]$Cwd)
    $hosts = New-Object System.Collections.Generic.List[string]
    if (-not $Cwd) { return @() }
    $dir = $Cwd
    for ($i = 0; $i -lt 6 -and $dir; $i++) {
        $cfg = Join-Path $dir '.git\config'
        if (Test-Path -LiteralPath $cfg -PathType Leaf) {
            try {
                $txt = Get-Content -LiteralPath $cfg -Raw -Encoding UTF8
                foreach ($m in [System.Text.RegularExpressions.Regex]::Matches($txt, '(?im)^\s*url\s*=\s*(.+?)\s*$')) {
                    $v = $m.Groups[1].Value.Trim()
                    $h = ''
                    $u = $null
                    if ([System.Uri]::TryCreate($v, [System.UriKind]::Absolute, [ref]$u) -and $u.Host) { $h = $u.Host }
                    elseif ($v -match '^(?:[\w.-]+@)?([A-Za-z0-9._-]+):') { $h = $Matches[1] }
                    if ($h) { $hosts.Add((Normalize-Host $h)) }
                }
            } catch { }
            break
        }
        $parent = Split-Path -Parent $dir
        if (-not $parent -or $parent -eq $dir) { break }
        $dir = $parent
    }
    return @($hosts)
}

# ---------------- 原生 JSON 回退 ----------------

function Emit-HookJson {
    param([string]$Decision, [string]$Reason, [string]$Context)
    $hso = [ordered]@{ hookEventName = 'PreToolUse'; permissionDecision = $Decision }
    if ($Reason) { $hso['permissionDecisionReason'] = $Reason }
    $payload = [ordered]@{ hookSpecificOutput = $hso }
    if ($Context) { $payload['additionalContext'] = $Context }
    $json = $payload | ConvertTo-Json -Depth 6 -Compress
    [Console]::Out.Write($json)
    [Console]::Out.Flush()
}

# ---------------- 弹窗 ----------------

function Show-GuardDialog {
    param([string]$Tool, [string[]]$TargetList, [string]$Evidence, [int]$TimeoutSec)
    if ($TimeoutSec -lt 3) { $TimeoutSec = 3 }
    try {
        Add-Type -AssemblyName System.Windows.Forms
        Add-Type -AssemblyName System.Drawing

        $form = New-Object System.Windows.Forms.Form
        $form.Text            = 'Upload Guard'
        $form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedSingle
        $form.MaximizeBox     = $false
        $form.MinimizeBox     = $false
        $form.TopMost         = $true
        $form.ShowInTaskbar   = $false
        $form.StartPosition   = 'Manual'
        $form.BackColor       = [System.Drawing.Color]::FromArgb(28, 28, 36)
        $form.Tag             = ''

        $w = 480
        $h = 310
        $wa = [System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea
        $offset = ($PID % 3) * 28
        $form.Size     = New-Object System.Drawing.Size($w, $h)
        $form.Location = New-Object System.Drawing.Point(($wa.Right - $w - 16), ($wa.Top + 16 + $offset))

        $title = New-Object System.Windows.Forms.Label
        $title.Text      = '  Upload Guard 检测到异常数据外发行为'
        $title.Font      = New-Object System.Drawing.Font('Microsoft YaHei UI', 11, [System.Drawing.FontStyle]::Bold)
        $title.ForeColor = [System.Drawing.Color]::FromArgb(255, 196, 90)
        $title.AutoSize  = $false
        $title.Bounds    = New-Object System.Drawing.Rectangle(0, 14, $w, 30)
        $form.Controls.Add($title)

        $shownTargets = $TargetList
        if ($shownTargets.Count -gt 4) {
            $shownTargets = @($shownTargets[0..3]) + @('...等 ' + $TargetList.Count + ' 个目标')
        }
        $body = New-Object System.Windows.Forms.Label
        $body.Text      = '工具:  ' + $Tool + $NL + '目标:  ' + ($shownTargets -join ', ') + $NL + $NL + $Evidence
        $body.Font      = New-Object System.Drawing.Font('Microsoft YaHei UI', 9)
        $body.ForeColor = [System.Drawing.Color]::Gainsboro
        $body.AutoSize  = $false
        $body.Bounds    = New-Object System.Drawing.Rectangle(18, 52, ($w - 36), 150)
        $form.Controls.Add($body)

        $count = New-Object System.Windows.Forms.Label
        $count.Font      = New-Object System.Drawing.Font('Microsoft YaHei UI', 9, [System.Drawing.FontStyle]::Italic)
        $count.ForeColor = [System.Drawing.Color]::FromArgb(150, 150, 160)
        $count.AutoSize  = $false
        $count.Bounds    = New-Object System.Drawing.Rectangle(18, 206, ($w - 36), 22)
        $form.Controls.Add($count)

        $clickHandler = {
            $btn = $args[0]
            $f = $btn.FindForm()
            if ($null -ne $f) { $f.Tag = [string]$btn.Tag; $f.Close() }
        }

        $btnDeny = New-Object System.Windows.Forms.Button
        $btnDeny.Text      = '截获并阻止'
        $btnDeny.Tag       = 'deny'
        $btnDeny.BackColor = [System.Drawing.Color]::FromArgb(192, 57, 57)
        $btnDeny.ForeColor = [System.Drawing.Color]::White
        $btnDeny.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
        $btnDeny.Bounds    = New-Object System.Drawing.Rectangle(18, 244, 136, 40)
        $btnDeny.Add_Click($clickHandler)
        $form.Controls.Add($btnDeny)
        $form.AcceptButton = $btnDeny
        $form.CancelButton = $btnDeny

        $btnAllow = New-Object System.Windows.Forms.Button
        $btnAllow.Text      = '放行本次'
        $btnAllow.Tag       = 'allow'
        $btnAllow.BackColor = [System.Drawing.Color]::FromArgb(52, 120, 72)
        $btnAllow.ForeColor = [System.Drawing.Color]::White
        $btnAllow.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
        $btnAllow.Bounds    = New-Object System.Drawing.Rectangle(166, 244, 136, 40)
        $btnAllow.Add_Click($clickHandler)
        $form.Controls.Add($btnAllow)

        $btnWl = New-Object System.Windows.Forms.Button
        $btnWl.Text      = '放行并加入白名单'
        $btnWl.Tag       = 'allow_wl'
        $btnWl.BackColor = [System.Drawing.Color]::FromArgb(44, 88, 148)
        $btnWl.ForeColor = [System.Drawing.Color]::White
        $btnWl.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
        $btnWl.Bounds    = New-Object System.Drawing.Rectangle(314, 244, 148, 40)
        $btnWl.Add_Click($clickHandler)
        $form.Controls.Add($btnWl)

        $form.Show()
        [void]$form.Activate()
        [datetime]$deadline = [datetime]::Now.AddSeconds($TimeoutSec)
        while ($form.Visible -and ([datetime]::Now -lt $deadline)) {
            [System.Windows.Forms.Application]::DoEvents()
            $remain = [int][Math]::Ceiling(($deadline - [datetime]::Now).TotalSeconds)
            $count.Text = ('{0} 秒内未选择将自动【截获并阻止】' -f $remain)
            Start-Sleep -Milliseconds 120
        }
        if ($form.Visible) { $form.Close() }
        $decision = [string]$form.Tag
        $form.Dispose()
        if (-not $decision) { $decision = 'deny' }
        return $decision
    } catch {
        try { Write-GuardLog -Tool $Tool -TargetList $TargetList -Evidence $Evidence -Decision 'error' -Reason ('弹窗异常: ' + $_.Exception.Message) -Session 'dialog-error' } catch { }
        return $null
    }
}

# ---------------- 主流程 ----------------

function Invoke-Guard {
    $raw = ''
    try {
        [Console]::InputEncoding = New-Object System.Text.UTF8Encoding($false)
        $raw = [Console]::In.ReadToEnd()
    } catch { $raw = '' }

    if (-not $raw) { exit 0 }

    $hookInput = $null
    try { $hookInput = $raw | ConvertFrom-Json } catch { $hookInput = $null }

    if (-not $hookInput -or -not $hookInput.tool_name) {
        $snip = ($raw -replace '\s+', ' ')
        $max  = [Math]::Min(120, $snip.Length)
        if ($max -lt 0) { $max = 0 }
        Write-GuardLog -Tool 'unknown' -TargetList @() -Evidence $snip.Substring(0, $max) -Decision 'allow' -Reason '钩子输入不可解析，默认放行（fail-open）' -Session 'parse-error'
        exit 0
    }

    $toolName = [string]$hookInput.tool_name
    $session  = 'unknown'
    if ($hookInput.session_id) { $session = [string]$hookInput.session_id }
    $cwd = ''
    if ($hookInput.cwd) { $cwd = [string]$hookInput.cwd }

    $cmdText = ''
    if ($hookInput.tool_input -and $hookInput.tool_input.command) { $cmdText = [string]$hookInput.tool_input.command }

    $filePath = ''
    if ($hookInput.tool_input -and $hookInput.tool_input.file_path) { $filePath = [string]$hookInput.tool_input.file_path }

    $contentText = ''
    if ($hookInput.tool_input) {
        foreach ($p in @('content', 'new_string', 'old_string', 'new_str', 'old_str')) {
            if ($hookInput.tool_input.$p) { $contentText += [string]$hookInput.tool_input.$p + $NL }
        }
        if ($hookInput.tool_input.edits) {
            try { $contentText += ($hookInput.tool_input.edits | ConvertTo-Json -Depth 6 -Compress) } catch { }
        }
    }

    $scanText = $cmdText
    if (-not $scanText) {
        try { $scanText = ($hookInput.tool_input | ConvertTo-Json -Depth 10 -Compress) } catch { $scanText = $raw }
    }
    if (-not $scanText) { exit 0 }

    $isShell     = $toolName -match '^(Bash|PowerShell)$'
    $isFileWrite = $toolName -match '^(Write|Edit|ApplyPatch|NotebookEdit)$'

    # URL: 文件写入工具不单独扫描正文 URL（避免写文档/代码时误报）
    $urlSource = ''
    if (-not $isFileWrite) { $urlSource = $scanText }
    $urlHosts = @(Get-UrlHosts -Text $urlSource)

    # UNC: 文件写入工具只检查写入目的地，不检查正文
    $uncSource = ''
    if (-not $isFileWrite) { $uncSource = $scanText }
    $uncHosts = @(Get-UncHosts -Text $uncSource -FilePath $filePath)

    $sigs = @()
    if ($isShell) {
        $sigs = @(Get-MatchedSignatures -Text $scanText)
    } elseif ($isFileWrite) {
        $contentSigs = @(Get-MatchedSignatures -Text $contentText)
        if ($contentSigs.Count -gt 0) {
            $sigs = $contentSigs
            $contentUrls = @(Get-UrlHosts -Text $contentText)
            if ($contentUrls.Count -gt 0) { $urlHosts = @($urlHosts + $contentUrls) }
        }
    }

    $targets = New-Object System.Collections.Generic.List[string]
    foreach ($h in $urlHosts) { $targets.Add($h) }
    foreach ($h in $uncHosts) { $targets.Add($h) }

    if ($sigs.Count -gt 0 -and $targets.Count -eq 0 -and -not $isFileWrite) {
        $targets.Add('(未知外发目标)')
    }

    if ($targets.Count -eq 0) { exit 0 }

    $evidParts = New-Object System.Collections.Generic.List[string]
    if ($cmdText) {
        $sn = ($cmdText -replace '\s+', ' ')
        if ($sn.Length -gt 150) { $sn = $sn.Substring(0, 150) + '...' }
        $evidParts.Add('命令: ' + $sn)
    } elseif ($filePath) {
        $evidParts.Add('文件: ' + $filePath)
    }
    if ($sigs.Count -gt 0) { $evidParts.Add('匹配特征: ' + ($sigs -join ', ')) }
    $evidenceText = ($evidParts -join $NL)

    $targetsArr = @($targets | Select-Object -Unique)

    # 无 URL 的 git 命令：尽力解析真实远端主机
    if (($targetsArr -contains '(未知外发目标)') -and ($cmdText -match '(?i)git\s+(push|remote)')) {
        $gh = @(Resolve-GitHosts -Cwd $cwd)
        if ($gh.Count -gt 0) {
            $targetsArr = @($targetsArr | Where-Object { $_ -ne '(未知外发目标)' })
            foreach ($h in $gh) { $targetsArr += $h }
            $targetsArr = @($targetsArr | Select-Object -Unique)
        }
    }

    $wl = Get-Whitelist
    $suspicious = @($targetsArr | Where-Object { -not (Test-HostWhitelisted -Target $_ -Hosts $wl.hosts) })

    if ($suspicious.Count -eq 0) {
        Write-GuardLog -Tool $toolName -TargetList $targetsArr -Evidence $evidenceText -Decision 'allow' -Reason '目标均在白名单中' -Session $session
        exit 0
    }

    # 命令白名单只用于「无法解析目标」的情况，不放过已解析出的真实外发目标
    $unknownOnly = @($suspicious | Where-Object { $_ -eq '(未知外发目标)' })
    if ($unknownOnly.Count -eq $suspicious.Count) {
        if (Test-CommandWhitelisted -CommandText $cmdText -Patterns $wl.commands) {
            Write-GuardLog -Tool $toolName -TargetList $targetsArr -Evidence $evidenceText -Decision 'allow' -Reason '命令命中命令白名单' -Session $session
            exit 0
        }
    }

    $headless   = ($env:UPLOAD_GUARD_HEADLESS -eq '1')
    $timeoutSec = 30
    if ($env:UPLOAD_GUARD_DIALOG_TIMEOUT_SEC -match '^\d+$') { $timeoutSec = [int]$env:UPLOAD_GUARD_DIALOG_TIMEOUT_SEC }

    $decision = ''
    $reason   = ''

    if ($headless) {
        if ($env:UPLOAD_GUARD_AUTO -eq 'allow') {
            $decision = 'allow'; $reason = '无头模式按 UPLOAD_GUARD_AUTO=allow 放行'
        } else {
            $decision = 'deny';  $reason = '无头模式失败安全默认截获'
        }
    } else {
        $dialogDecision = $null
        try { $dialogDecision = Show-GuardDialog -Tool $toolName -TargetList $suspicious -Evidence $evidenceText -TimeoutSec $timeoutSec } catch { $dialogDecision = $null }

        if ($dialogDecision -eq 'allow_wl') {
            $newHosts = @($wl.hosts)
            foreach ($t in $suspicious) {
                if ($t -ne '(未知外发目标)' -and ($newHosts -notcontains $t)) { $newHosts += $t }
            }
            $saved = $true
            try { Save-Whitelist -Hosts $newHosts -Commands $wl.commands } catch { $saved = $false }
            $decision = 'allow'
            if ($saved) { $reason = '用户选择放行并加入白名单' } else { $reason = '用户选择放行并加入白名单（写盘失败，仅本次生效）' }
        } elseif ($dialogDecision -eq 'allow') {
            $decision = 'allow'; $reason = '用户选择放行本次'
        } elseif ($dialogDecision -eq 'deny') {
            $decision = 'deny';  $reason = '用户选择截获，或超时未响应（失败安全截获）'
        } else {
            if ($env:UPLOAD_GUARD_NATIVE_ASK -eq '0') {
                $decision = 'deny'; $reason = '弹窗不可用且已禁用原生确认（失败安全截获）'
            } else {
                $reason = '弹窗不可用，已回退 ZCode 原生确认'
                Write-GuardLog -Tool $toolName -TargetList $targetsArr -Evidence $evidenceText -Decision 'ask' -Reason $reason -Session $session
                try { Emit-HookJson -Decision 'ask' -Reason $reason -Context '' ; exit 0 } catch { exit 2 }
            }
        }
    }

    if ($decision -eq 'allow') {
        Write-GuardLog -Tool $toolName -TargetList $targetsArr -Evidence $evidenceText -Decision 'allow' -Reason $reason -Session $session
        exit 0
    }

    $targetStr = ($suspicious -join ', ')
    Write-GuardLog -Tool $toolName -TargetList $targetsArr -Evidence $evidenceText -Decision 'deny' -Reason $reason -Session $session
    [Console]::Error.WriteLine('Upload Guard 已截获: 工具 [' + $toolName + '] 试图将数据外发到 ' + $targetStr + '。(' + $reason + ') 若该行为合法，请在弹窗中选择放行，或将目标加入白名单 (' + $WhitelistPath + ')。')
    exit 2
}

try {
    Invoke-Guard
    exit 0
} catch {
    try {
        Write-GuardLog -Tool 'internal' -TargetList @() -Evidence ('钩子内部错误: ' + $_.Exception.Message) -Decision 'allow' -Reason 'fail-open: 守卫内部错误，已放行（请查看日志）' -Session 'internal-error'
    } catch { }
    exit 0
}
