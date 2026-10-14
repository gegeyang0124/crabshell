@echo off

set YYYYmmdd=%date:~0,4%%date:~5,2%%date:~8,2%
echo %YYYYmmdd%
set hhmm=%time:~0,2%%time:~3,2%
set hhmm=%hhmm: =0%
echo  %hhmm%
set time24=%YYYYmmdd%%hhmm%
echo  %time24%

:: 第零步:查找本目录中的jks证书(文件名格式: 别名_密码.jks,密码取'_'之后'.'之前的字符串)
set "JKS_FILE="
for %%J in (*.jks) do if not defined JKS_FILE set "JKS_FILE=%%J"
if not defined JKS_FILE (
    echo 当前目录未找到jks签名证书文件
    goto :eof
)
for /f "tokens=1* delims=_" %%A in ("%JKS_FILE:~0,-4%") do (
    set "KS_ALIAS=%%A"
    set "KS_PASS=%%B"
)
if not defined KS_PASS (
    echo jks文件名 %JKS_FILE% 不符合 别名_密码.jks 格式,无法解析密码
    goto :eof
)
echo 使用签名证书: %JKS_FILE%  别名: %KS_ALIAS%  密码: %KS_PASS%

:: 第一步:获取当前目录所有_unsigned.apk加固产物清单
echo 查找_unsigned.apk加固产物...
set FILE_COUNT=0
for /f "delims=" %%F in ('dir /b *_unsigned.apk') do (
    set /a FILE_COUNT+=1
    echo   %%F
)
if %FILE_COUNT%==0 (
    echo 当前目录未找到需要签名的_unsigned.apk文件
    goto :eof
)
echo 共找到 %FILE_COUNT% 个待签名文件

:: 第二步:逐个文件加签(zipalign对齐后apksigner签名)
:: 签名输出文件名去掉_unsigned(使用call set二次展开实现字符串替换,避免延迟扩展在循环内失效的问题)
for /f "delims=" %%F in ('dir /b *_unsigned.apk') do (
    call set "SIGN_BASE=%%~nF"
    call set "SIGN_BASE=%%SIGN_BASE:_unsigned=%%"
    call echo %%F to %%SIGN_BASE%%
    echo %%~nF.zipa
    zipalign -p -f -v 4 %%F %%~nF.zipa
    echo zipalign finish

    call echo %%SIGN_BASE%%_%time24%.apk
    call apksigner sign --ks %JKS_FILE% --v2-signing-enabled true --ks-key-alias %KS_ALIAS% --ks-pass pass:%KS_PASS% --key-pass pass:%KS_PASS% --out %%SIGN_BASE%%_%time24%.apk %%~nF.zipa
    echo sign finish
)
