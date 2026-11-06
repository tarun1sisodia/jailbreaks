@echo off
setlocal enabledelayedexpansion

echo ==========================================================
echo        WebProbe - Full Security Audit Scanner
echo ==========================================================

REM Determine target
set TARGET=%1
if "%TARGET%"=="" (
    set /p TARGET="Enter target URL or config path [default: config/agraskbagheltourandtravels.json]: "
)
if "%TARGET%"=="" (
    set TARGET=config/agraskbagheltourandtravels.json
)

REM Check if target is a file or a URL
if exist "%TARGET%" (
    set TARGET_FLAG=--config "%TARGET%"
) else (
    set TARGET_FLAG="%TARGET%"
)

REM Setup reports directory
if not exist "reports" mkdir reports

REM Generate timestamp
for /f "tokens=2 delims==" %%I in ('wmic os get localdatetime /value 2^>nul') do set dt=%%I
if not "%dt%"=="" (
    set TS=%dt:~0,8%_%dt:~8,6%
) else (
    set TS=%RANDOM%
)

set REPORT_JSON=reports\scan_%TS%.json
set REPORT_MD=reports\scan_%TS%.md
set REPORT_SARIF=reports\scan_%TS%.sarif
set REPORT_LOG=reports\audit_%TS%.tsv

echo [*] Target        : %TARGET%
echo [*] Profile       : full
echo [*] Report (JSON) : %REPORT_JSON%
echo [*] Report (MD)   : %REPORT_MD%
echo [*] Safety        : AIMD active, PII redacted, Rate-limit 3 rps
echo.
echo [*] Press Ctrl+C or touch 'webprobe.abort' to stop at any time.
echo.

python webprobe.py %TARGET_FLAG% --profile full --rate-limit 3 --aimd --redact --json -o "%REPORT_JSON%" --md "%REPORT_MD%" --sarif --sarif-path "%REPORT_SARIF%" --activity-log "%REPORT_LOG%"

if %ERRORLEVEL% equ 0 (
    echo.
    echo [+] Scan completed successfully.
    echo [+] Markdown report: %REPORT_MD%
    echo [+] JSON report    : %REPORT_JSON%
    echo [+] SARIF report   : %REPORT_SARIF%
) else (
    echo.
    echo [!] Scan exited with code %ERRORLEVEL%. Check logs for details.
)

pause

