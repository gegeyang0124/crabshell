@echo off
:: 动态获取脚本所在目录,生成kapp_payload.bin路径(%~dp0为bat所在目录,带尾随反斜杠)
set PAYLOAD_PATH=%~dp0kapp_payload.bin
:: 输出路径为当前目录,文件名=原apk文件名_unsigned.apk

:: 国内GitHub镜像加速(优先镜像,失败回退原始地址)
set GH_MIRROR=https://cors.isteed.cc/github.com
set CRABSHELL_APKTOOL_URLS=%GH_MIRROR%/iBotPeaches/Apktool/releases/download/v2.11.1/apktool_2.11.1.jar

:: 编译环境配置(Rust/cargo + Android NDK)
set PATH=%USERPROFILE%\.cargo\bin;%PATH%
set ANDROID_NDK_HOME=D:\Android\Sdk\ndk\28.2.13676358

:: 切换到crabshell源码目录执行pack.py
cd /d F:\jiagou\crabshell

:: ===== 需要保留为明文(不加密进payload)的原生库白名单 =====
:: 背景:本应用 manifest 为 extractNativeLibs=false,原始so直接STORED+页对齐存放在APK内由系统mmap加载。
:: 百度人脸 libbdface_sdk.so 采用静态JNI符号导出(Java_com_baidu_idl_main_facesdk_FaceAuth_*),
:: 且其 DT_NEEDED 依赖同为payload的 libonnxruntime.so / libbd_facecollect_unifylicense.so / libc++_shared.so;
:: libaikl_cluster_arm.so 又依赖 libaikl_calc_arm.so。加固后这些库被移出APK真实lib目录、解密到cache目录,
:: SDK内部 System.loadLibrary("bdface_sdk") 在解析 DT_NEEDED(兄弟payload库)时 dlopen 失败,
:: 而百度把该异常用 try-catch 吞掉(日志 "bd_facecollect_unifylicense load Exception"),
:: 直到调用native方法才暴露为 "No implementation found ... FaceAuth.nativeSetCoreConfigure"。
:: 仅系统库依赖的so(如libserial_port.so)不受影响,故只有人脸SDK崩溃。
:: 解决:用 --keep-lib 把这一整簇存在“payload内部互相依赖”的库保留为STORED明文留在APK内,
:: 使其加载路径与 DT_NEEDED 解析与加固前完全一致(zipalign -p 会重新页对齐,满足 extractNativeLibs=false)。::
:: 弘圣H212: libdk_serial_port.so 的 DT_SONAME 与 libserial_port.so 撞名(厂商改名同源库),payload化后在H212的
:: OEM ROM上壳DexPathList补丁失效时预加载登记SONAME而非文件名,loadLibrary按名dlopen报not found崩溃。
:: 解决: 该撞名库对保留STORED明文在APK内, 加载语义与加固前一致。
set KEEP_LIBS=--keep-lib bdface_sdk --keep-lib bd_facecollect_unifylicense --keep-lib onnxruntime --keep-lib c++_shared --keep-lib aikl_calc_arm --keep-lib aikl_cluster_arm --keep-lib dk_serial_port --keep-lib serial_port

:: 逐个加固当前目录所有apk(跳过已加固的*_unsigned.apk)
for %%F in ("%~dp0*.apk") do (
    echo %%~nxF | findstr /i "_unsigned" >nul || (
        echo.
        echo ===== 开始加固: %%~nxF =====
        python pack.py --target "%%~fF" --output "%~dp0%%~nF_unsigned.apk" --no-sign %KEEP_LIBS%
        if exist "%PAYLOAD_PATH%" (
            del "%PAYLOAD_PATH%"
            echo 已删除中间文件: %PAYLOAD_PATH%
        )
    )
)
