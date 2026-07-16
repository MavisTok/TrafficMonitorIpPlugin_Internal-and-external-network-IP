$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot

function Read-Text($relativePath) {
    $path = Join-Path $repoRoot $relativePath
    if (-not (Test-Path -LiteralPath $path)) {
        throw "Missing file: $relativePath"
    }
    return Get-Content -LiteralPath $path -Raw -Encoding UTF8
}

function Assert-Match($name, $content, $pattern) {
    if ($content -notmatch $pattern) {
        throw "Missing expected content: $name"
    }
    Write-Host "OK: $name"
}

function Assert-Contains($name, $content, $needle) {
    if (-not $content.Contains($needle)) {
        throw "Missing expected content: $name"
    }
    Write-Host "OK: $name"
}

$pluginOptions = Read-Text 'src/plugin_options.h'
$resourceHeader = Read-Text 'res/resource.h'
$pluginRc = Read-Text 'res/plugin.rc'
$optionsDialog = Read-Text 'src/options_dialog.cpp'
$pluginCpp = Read-Text 'src/plugin.cpp'
$saveKeyNeedle = @'
WritePrivateProfileStringW(L"ip", L"enable_exit_detection"
'@
$saveValueNeedle = @'
options_.enable_exit_detection ? L"1" : L"0"
'@
$loadKeyNeedle = @'
L"enable_exit_detection"
'@
$loadDefaultNeedle = @'
options_.enable_exit_detection ? 1 : 0
'@

Assert-Match 'PluginOptions default disables exit detection' `
    $pluginOptions 'bool\s+enable_exit_detection\s*=\s*false\s*;'

Assert-Match 'resource ID IDC_CHECK_EXIT_DETECTION is 1007' `
    $resourceHeader '#define\s+IDC_CHECK_EXIT_DETECTION\s+1007\b'

Assert-Match 'options dialog height is 180' `
    $pluginRc 'IDD_OPTIONS\s+DIALOGEX\s+0,\s+0,\s+250,\s+180\b'

Assert-Match 'exit detection checkbox is present around y=115' `
    $pluginRc 'IDC_CHECK_EXIT_DETECTION[^\r\n]*,\s*10,\s*115,\s*\d+,\s*12'

$exitDetectionLabel = -join ([char]0x542F, [char]0x7528, [char]0x51FA, [char]0x53E3, [char]0x68C0, [char]0x6D4B)
Assert-Contains 'exit detection checkbox label is correct' `
    $pluginRc "CONTROL `"$exitDetectionLabel`", IDC_CHECK_EXIT_DETECTION"

Assert-Match 'OK button moved to y=145' `
    $pluginRc 'DEFPUSHBUTTON\s+[^,\r\n]+,\s*IDOK,\s*110,\s*145,\s*50,\s*14'

Assert-Match 'Cancel button moved to y=145' `
    $pluginRc 'PUSHBUTTON\s+[^,\r\n]+,\s*IDCANCEL,\s*170,\s*145,\s*50,\s*14'

Assert-Match 'options dialog initializes exit detection checkbox' `
    $optionsDialog 'SetCheck\(hDlg,\s*IDC_CHECK_EXIT_DETECTION,\s*s_opts->enable_exit_detection\)'

Assert-Match 'options dialog reads exit detection checkbox' `
    $optionsDialog 'new_opts\.enable_exit_detection\s*=\s*GetCheck\(hDlg,\s*IDC_CHECK_EXIT_DETECTION\)'

Assert-Match 'options dialog changed check includes exit detection' `
    $optionsDialog 'new_opts\.enable_exit_detection\s*!=\s*s_opts->enable_exit_detection'

Assert-Contains 'LoadOptions reads enable_exit_detection key' `
    $pluginCpp $loadKeyNeedle

Assert-Contains 'LoadOptions uses current enable_exit_detection default' `
    $pluginCpp $loadDefaultNeedle

Assert-Contains 'SaveOptions writes enable_exit_detection key' `
    $pluginCpp $saveKeyNeedle

Assert-Contains 'SaveOptions writes enable_exit_detection value' `
    $pluginCpp $saveValueNeedle

Assert-Match 'plugin declares exit detection tooltip helper' `
    (Read-Text 'src/plugin.h') 'void\s+AppendExitDetectionTooltip\(\)'

Assert-Match 'DataRequired refreshes exit detection only when enabled' `
    $pluginCpp 'if\s*\(\s*options_\.enable_exit_detection\s*\)\s*\{[\s\S]*exit_detection::RequestRefreshAsync\(force_refresh_requested\)'

Assert-Match 'empty tooltip path appends exit detection' `
    $pluginCpp 'AppendClaudeRiskTooltip\(\);\s*AppendExitDetectionTooltip\(\);\s*return;'

Assert-Match 'normal tooltip path appends exit detection after Claude risk' `
    $pluginCpp 'AppendClaudeRiskTooltip\(\);\s*AppendExitDetectionTooltip\(\);'

Assert-Match 'exit detection tooltip uses formatted snapshot' `
    $pluginCpp 'exit_detection::FormatTooltip\(exit_detection::GetSnapshot\(\)\)'

Write-Host 'OK: exit detection option is integrated into refresh and tooltip'

Write-Host 'All exit detection option checks passed.'
