# Windows WinFsp mount smoke test: for each row in manifest.tsv, mount the
# fixture to a drive letter, read the known file through the mount, assert it.
# The WinFsp backend renders the ForensicFs tree at the mount root (no ro/
# overlay), so the read path is <drive>\<subpath> for every layout.
#
# Usage: scripts/smoke/smoke.ps1 -Bin <4n6mount.exe> -Fix <fixtures-dir>
param(
  [Parameter(Mandatory=$true)][string]$Bin,
  [Parameter(Mandatory=$true)][string]$Fix
)
$ErrorActionPreference = 'SilentlyContinue'
$manifest = Join-Path $PSScriptRoot 'manifest.tsv'
$env:PATH = "C:\Program Files (x86)\WinFsp\bin;" + $env:PATH
$drive = 'Z:'
$pass = 0; $fail = 0

foreach ($line in Get-Content $manifest) {
  if ($line -match '^\s*#' -or $line.Trim() -eq '') { continue }
  $c = $line -split "`t"
  $name = $c[0]; $fixture = $c[1]; $flag = $c[2]; $subpath = $c[4]; $expected = $c[5]

  Get-Process 4n6mount -ErrorAction SilentlyContinue | Stop-Process -Force
  Start-Sleep 1
  $p = Start-Process $Bin -ArgumentList "$Fix\$fixture","$drive","--fs",$flag -PassThru -WindowStyle Hidden
  Start-Sleep 6

  $readpath = "$drive\" + ($subpath -replace '/','\')
  $content = Get-Content $readpath -Raw -ErrorAction SilentlyContinue
  if ($content -and $content.Contains($expected)) {
    Write-Output "PASS  $name  ($readpath contains '$expected')"; $pass++
  } else {
    Write-Output "FAIL  $name  — '$expected' not found at $readpath"
    Write-Output ("      drive exists=" + (Test-Path "$drive\") + "  readpath exists=" + (Test-Path $readpath))
    $fail++
  }
  Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
  Start-Sleep 1
}

Write-Output "=== WinFsp smoke: $pass passed, $fail failed ==="
exit $fail
