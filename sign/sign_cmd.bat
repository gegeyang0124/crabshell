@echo off

set YYYYmmdd=%date:~0,4%%date:~5,2%%date:~8,2%
echo %YYYYmmdd%
set hhmm=%time:~0,2%%time:~3,2%
set hhmm=%hhmm: =0%
echo  %hhmm%
set time24=%YYYYmmdd%%hhmm%
echo  %time24%

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
    call apksigner sign --ks pos.jks --v2-signing-enabled true --ks-key-alias pos --ks-pass pass:123456 --key-pass pass:123456 --out %%SIGN_BASE%%_%time24%.apk %%~nF.zipa
    echo sign finish
)
