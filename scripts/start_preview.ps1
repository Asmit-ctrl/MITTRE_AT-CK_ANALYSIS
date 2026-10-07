# Local development helper. Refresh only a process launched from this checkout.
$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path -Parent $PSScriptRoot
$taskRuntime = Join-Path $taskRoot '.runtime'
$taskPython = Join-Path $taskRoot '.venv\Scripts\python.exe'
New-Item -ItemType Directory -Path $taskRuntime -Force | Out-Null
$taskPidFile = Join-Path $taskRuntime 'server.pid'
if ((& $taskPython (Join-Path $PSScriptRoot 'active_analyses.py')) -gt 0) {
    throw 'An analysis is running. Retry the preview refresh after it finishes; original evidence remains saved.'
}
if (Test-Path -LiteralPath $taskPidFile) {
    $taskPid = [int](Get-Content -LiteralPath $taskPidFile)
    $taskInfo = Get-CimInstance Win32_Process -Filter "ProcessId=$taskPid"
    if ($taskInfo -and $taskInfo.CommandLine -match 'uvicorn app.main:app' -and $taskInfo.ExecutablePath -eq $taskPython) {
        Stop-Process -Id $taskPid -Force
    }
}
$taskProcess = Start-Process -FilePath $taskPython -ArgumentList @('-m','uvicorn','app.main:app','--host','127.0.0.1','--port','8765') -WorkingDirectory $taskRoot -RedirectStandardOutput (Join-Path $taskRuntime 'server.out.log') -RedirectStandardError (Join-Path $taskRuntime 'server.err.log') -WindowStyle Hidden -PassThru
$taskProcess.Id | Set-Content -LiteralPath $taskPidFile
Write-Output 'Shiftline local preview: http://127.0.0.1:8765'
