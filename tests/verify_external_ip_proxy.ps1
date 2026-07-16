$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$ipUtils = Get-Content -LiteralPath (Join-Path $repoRoot 'src/ip_utils.cpp') -Raw -Encoding UTF8

if ($ipUtils -match 'WinHttpOpen\([\s\S]*?WINHTTP_ACCESS_TYPE_DEFAULT_PROXY') {
    throw 'GetExternalIPv4WithCountry must not use WINHTTP_ACCESS_TYPE_DEFAULT_PROXY; stale WinHTTP system proxy can make external IP show N/A.'
}

if ($ipUtils -notmatch 'WinHttpOpen\([\s\S]*?WINHTTP_ACCESS_TYPE_NO_PROXY') {
    throw 'GetExternalIPv4WithCountry should open a no-proxy session and apply current-user proxy per request.'
}

if ($ipUtils -notmatch 'ApplyCurrentUserProxyForRequest\(hRequest,\s*request_url\.c_str\(\)\)') {
    throw 'GetExternalIPv4WithCountry must still apply current-user proxy settings per request.'
}

Write-Host 'External IP proxy checks passed.'
