zipalign -p -f -v 4 app.apk app_zipa.apk
apksigner sign --ks pos.jks --v2-signing-enabled true --ks-key-alias pos --ks-pass pass:123456 --key-pass pass:123456 --out app_zipa_sign.apk  app_zipa.apk

apksigner sign --v3-signing-enabled true --ks my-release-key.keystore --ks-pass pass:your_keystore_password --ks-key-alias my-key-alias --key-pass pass:your_key_password --out output-file.apk input-file.apk

超时：timeout /t 1 /nobreak >nul