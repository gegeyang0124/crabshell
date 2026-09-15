@echo off
:: 获取脚本所在目录
set SCRIPT_DIR=%~dp0

echo ===== 步骤1: 加固APK =====
cd /d "%SCRIPT_DIR%"
call strong_cmd.bat
echo [debug] 加固步骤已返回

echo.
echo ===== 步骤2: 签名APK =====
cd /d "%SCRIPT_DIR%"
cmd /c sign_cmd.bat
echo [debug] 签名步骤已返回

echo.
echo ===== 步骤3: 清理临时文件 =====
cd /d "%SCRIPT_DIR%"
cmd /c del_cmd.bat
echo [debug] 清理步骤已返回

echo.
echo ===== 全部执行完毕 =====
