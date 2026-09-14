use jni::JNIEnv;
use jni::objects::{JClass, JObject, JString, JValue, JObjectArray, JByteArray};
use jni::sys::{jint, JNI_VERSION_1_6};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce
};
use std::os::raw::c_void;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{Read, Write, Seek, SeekFrom};
use std::sync::atomic::{AtomicBool, Ordering};
use zip::ZipArchive;

mod config;
mod strings_config;
#[macro_use]
mod obfuscate;
use config::{get_aes_key, PAYLOAD_HASH, EXPECTED_SIGNATURE_HASH};
use sha2::{Sha256, Digest};

#[macro_use]
extern crate log;
use android_logger::Config;

static DEX_LOAD_MARKER: AtomicBool = AtomicBool::new(false);

fn try_mark_dex_load_started() -> bool {
    DEX_LOAD_MARKER
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
}

fn clear_dex_load_marker() {
    DEX_LOAD_MARKER.store(false, Ordering::Release);
}

#[cfg(test)]
fn clear_dex_load_marker_for_tests() {
    clear_dex_load_marker();
}

#[no_mangle]
pub extern "system" fn JNI_OnLoad(_vm: jni::JavaVM, _reserved: *mut c_void) -> jint {
    android_logger::init_once(
        Config::default()
            .with_tag(s!(strings_config::LOG_TAG))
            .with_max_level(log::LevelFilter::Debug),
    );
    info!("Native library loaded, JNI_OnLoad called");

    // Anti-Debug: Check TracerPid and Ptrace
    check_debugger();

    JNI_VERSION_1_6
}

fn check_debugger() {
    // 1. Check TracerPid
    if let Ok(content) = std::fs::read_to_string(&s!(strings_config::PROC_STATUS)) {
        for line in content.lines() {
            if line.starts_with(&s!(strings_config::TRACER_PID)) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() > 1 {
                    let pid_str = parts[1];
                    info!("{} {}", s!(strings_config::TRACER_PID), pid_str);
                    if let Ok(pid) = pid_str.parse::<i32>() {
                        if pid > 0 {
                            error!("{} {}={}! {}", 
                                s!(strings_config::DEBUG_DETECTED), 
                                s!(strings_config::TRACER_PID), 
                                pid, 
                                s!(strings_config::EXITING));
                            std::process::exit(1);
                        }
                    }
                }
            }
        }
    }

    // NOTE: PTRACE_TRACEME removed — on some Android ROMs it interferes with
    // ART runtime and Zygote process management, causing the app to hang on
    // the splash screen.  TracerPid check above is sufficient for debugger
    // detection.
}

fn call_object_method<'local>(
    env: &mut JNIEnv<'local>,
    obj: &JObject<'local>,
    method: &str,
    sig: &str,
) -> Result<JObject<'local>, jni::errors::Error> {
    env.call_method(obj, method, sig, &[])?.l()
}

fn call_string_method<'local>(
    env: &mut JNIEnv<'local>,
    obj: &JObject<'local>,
    method: &str,
    sig: &str,
) -> Result<String, jni::errors::Error> {
    let value = call_object_method(env, obj, method, sig)?;
    Ok(env.get_string(&JString::from(value))?.into())
}

fn get_string_field<'local>(
    env: &mut JNIEnv<'local>,
    obj: &JObject<'local>,
    field: &str,
) -> Result<String, jni::errors::Error> {
    let value = env.get_field(obj, field, "Ljava/lang/String;")?.l()?;
    Ok(env.get_string(&JString::from(value))?.into())
}

fn get_paths_and_loader_from_context<'local>(
    env: &mut JNIEnv<'local>,
    context: &JObject<'local>,
) -> Result<(String, String, JObject<'local>), jni::errors::Error> {
    let cache_dir = call_object_method(env, context, "getCacheDir", "()Ljava/io/File;")?;
    let cache_path = call_string_method(env, &cache_dir, "getAbsolutePath", "()Ljava/lang/String;")?;

    let class_loader = call_object_method(env, context, "getClassLoader", "()Ljava/lang/ClassLoader;")?;

    let files_dir = call_object_method(env, context, "getFilesDir", "()Ljava/io/File;")?;
    let data_dir = call_object_method(env, &files_dir, "getParentFile", "()Ljava/io/File;")?;
    let data_path = call_string_method(env, &data_dir, "getAbsolutePath", "()Ljava/lang/String;")?;

    Ok((cache_path, data_path, class_loader))
}

#[no_mangle]
pub extern "system" fn Java_com_kapp_shell_ShellApplication_nativeLoadDex<'local>(
    mut env: JNIEnv<'local>,
    _this: JObject<'local>,
    context: JObject<'local>,
    sdk_int: jint,
) {
    info!("{} {}", s!(strings_config::MSG_NATIVE_LOAD_DEX).replace("{}", ""), sdk_int);
    if !try_mark_dex_load_started() {
        info!("nativeLoadDex (Application): dex already loaded in process, skipping duplicate call");
        return;
    }
    let apk_path = match get_package_code_path(&mut env, &context) {
        Ok(path) => path,
        Err(e) => {
            error!("Failed to get package code path: {:?}", e);
            let _ = env.exception_clear();
            clear_dex_load_marker();
            return;
        }
    };

    let (cache_path_str, data_path_str, class_loader) =
        match get_paths_and_loader_from_context(&mut env, &context) {
            Ok(values) => values,
            Err(e) => {
                error!("nativeLoadDex (Application): failed to resolve paths/classloader: {:?}", e);
                let _ = env.exception_clear();
                clear_dex_load_marker();
                return;
            }
        };

    if let Err(e) = verify_integrity(&mut env, &context) {
        error!("Integrity check failed: {:?}", e);
        let _ = env.exception_clear();
        clear_dex_load_marker();
        return;
    }

    // Fast path: check cache marker to skip expensive payload decryption
    let payload = if let Some(cached_names) = read_cache_marker(&cache_path_str, &apk_path) {
        let cached_payload: Vec<(String, Vec<u8>)> = cached_names.into_iter().map(|n| (n, Vec::new())).collect();
        if is_cache_valid(&cache_path_str, &data_path_str, &cached_payload) {
            info!("nativeLoadDex (Application): cache valid, skipping payload extraction");
            cached_payload
        } else {
            match extract_payload(&apk_path, true) {
                Ok(p) => { write_cache_marker(&cache_path_str, &apk_path, &p); p }
                Err(e) => {
                    error!("Payload integrity failed: {:?}", e);
                    clear_dex_load_marker();
                    return;
                }
            }
        }
    } else {
        match extract_payload(&apk_path, true) {
            Ok(p) => { write_cache_marker(&cache_path_str, &apk_path, &p); p }
            Err(e) => {
                error!("Payload integrity failed: {:?}", e);
                clear_dex_load_marker();
                return;
            }
        }
    };

    if let Err(e) =
        load_dex_core(&mut env, &cache_path_str, &data_path_str, &class_loader, &payload, sdk_int)
    {
        error!("nativeLoadDex (Application) failed: {:?}", e);
        let _ = env.exception_clear();
        clear_dex_load_marker();
    }
}

#[no_mangle]
pub extern "system" fn Java_com_kapp_shell_ShellApplication_nativeLoadDexWithAppInfo<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    app_info: JObject<'local>,
    class_loader: JObject<'local>,
    sdk_int: jint,
) {
    info!("{} {}", s!(strings_config::MSG_NATIVE_LOAD_DEX).replace("{}", ""), sdk_int);
    if !try_mark_dex_load_started() {
        info!("nativeLoadDexWithAppInfo: dex already loaded in process, skipping duplicate call");
        return;
    }
    
    // 1. Get APK path and data dir from ApplicationInfo
    let apk_path = match get_string_field(&mut env, &app_info, "sourceDir") {
        Ok(value) => value,
        Err(e) => {
            error!("nativeLoadDexWithAppInfo: failed to read sourceDir: {:?}", e);
            let _ = env.exception_clear();
            clear_dex_load_marker();
            return;
        }
    };

    let data_dir = match get_string_field(&mut env, &app_info, "dataDir") {
        Ok(value) => value,
        Err(e) => {
            error!("nativeLoadDexWithAppInfo: failed to read dataDir: {:?}", e);
            let _ = env.exception_clear();
            clear_dex_load_marker();
            return;
        }
    };
    let cache_path_str = format!("{}/cache", data_dir);
    if let Err(e) = std::fs::create_dir_all(&cache_path_str) {
        error!(
            "nativeLoadDexWithAppInfo: failed to create cache dir {}: {}",
            cache_path_str, e
        );
        clear_dex_load_marker();
        return;
    }

    // 2. Verify Integrity (Skip for now if we only have app_info, or pass JObject::null())
    // For now, we skip signature check here to avoid complexity of getting PM from app_info.
    // It will be verified in nativeLoadDex or BootstrapProvider anyway.
    // Fast path: check cache marker to skip expensive payload decryption
    let payload = if let Some(cached_names) = read_cache_marker(&cache_path_str, &apk_path) {
        let cached_payload: Vec<(String, Vec<u8>)> = cached_names.into_iter().map(|n| (n, Vec::new())).collect();
        if is_cache_valid(&cache_path_str, &data_dir, &cached_payload) {
            info!("nativeLoadDexWithAppInfo: cache valid, skipping payload extraction");
            cached_payload
        } else {
            match extract_payload(&apk_path, true) {
                Ok(p) => { write_cache_marker(&cache_path_str, &apk_path, &p); p }
                Err(e) => {
                    error!("Payload integrity failed: {:?}", e);
                    clear_dex_load_marker();
                    return;
                }
            }
        }
    } else {
        match extract_payload(&apk_path, true) {
            Ok(p) => { write_cache_marker(&cache_path_str, &apk_path, &p); p }
            Err(e) => {
                error!("Payload integrity failed: {:?}", e);
                clear_dex_load_marker();
                return;
            }
        }
    };

    // 3. Load DEX using the modular core
    if let Err(e) = load_dex_core(
        &mut env,
        &cache_path_str,
        &data_dir,
        &class_loader,
        &payload,
        sdk_int,
    ) {
        error!("nativeLoadDexWithAppInfo failed: {:?}", e);
        let _ = env.exception_clear();
        clear_dex_load_marker();
    }
}

#[no_mangle]
pub extern "system" fn Java_com_kapp_shell_BootstrapProvider_nativeLoadDex<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    context: JObject<'local>,
    sdk_int: jint,
) {
    info!("nativeLoadDex (Provider) called for SDK {}", sdk_int);
    if !try_mark_dex_load_started() {
        info!("nativeLoadDex (Provider): dex already loaded in process, skipping duplicate call");
        return;
    }
    let apk_path = match get_package_code_path(&mut env, &context) {
        Ok(path) => path,
        Err(e) => {
            error!("Failed to get package code path (Provider): {:?}", e);
            let _ = env.exception_clear();
            clear_dex_load_marker();
            return;
        }
    };

    let (cache_path_str, data_path_str, class_loader) =
        match get_paths_and_loader_from_context(&mut env, &context) {
            Ok(values) => values,
            Err(e) => {
                error!("nativeLoadDex (Provider): failed to resolve paths/classloader: {:?}", e);
                let _ = env.exception_clear();
                clear_dex_load_marker();
                return;
            }
        };

    if let Err(e) = verify_integrity(&mut env, &context) {
        error!("Integrity check failed: {:?}", e);
        let _ = env.exception_clear();
        clear_dex_load_marker();
        return;
    }

    // Fast path: check cache marker to skip expensive payload decryption
    let payload = if let Some(cached_names) = read_cache_marker(&cache_path_str, &apk_path) {
        let cached_payload: Vec<(String, Vec<u8>)> = cached_names.into_iter().map(|n| (n, Vec::new())).collect();
        if is_cache_valid(&cache_path_str, &data_path_str, &cached_payload) {
            info!("nativeLoadDex (Provider): cache valid, skipping payload extraction");
            cached_payload
        } else {
            match extract_payload(&apk_path, true) {
                Ok(p) => { write_cache_marker(&cache_path_str, &apk_path, &p); p }
                Err(e) => {
                    error!("Payload integrity failed: {:?}", e);
                    clear_dex_load_marker();
                    return;
                }
            }
        }
    } else {
        match extract_payload(&apk_path, true) {
            Ok(p) => { write_cache_marker(&cache_path_str, &apk_path, &p); p }
            Err(e) => {
                error!("Payload integrity failed: {:?}", e);
                clear_dex_load_marker();
                return;
            }
        }
    };

    if let Err(e) =
        load_dex_core(&mut env, &cache_path_str, &data_path_str, &class_loader, &payload, sdk_int)
    {
        error!("nativeLoadDex (Provider) failed: {:?}", e);
        let _ = env.exception_clear();
        clear_dex_load_marker();
    }
}

/// Cross-process advisory lock (flock) that serializes payload landing.
///
/// Multi-process apps (e.g. getui `:pushservice`, Bugly) start several
/// processes at once; each one runs the shell and would otherwise decrypt and
/// write the SAME shared `.dex`/`.so` files concurrently, interleaving writes
/// and leaving truncated/corrupt artifacts that crash `dlopen`/dexopt at
/// startup. Only the lock winner extracts; the others block here, then find a
/// complete cache and skip straight to class-loader registration.
struct ProcessLock {
    fd: i32,
}

impl ProcessLock {
    /// Acquire a blocking, exclusive cross-process lock on `path`.
    /// Best-effort: if the lock file cannot be opened/locked the loader still
    /// proceeds (fd = -1), degrading to the previous single-process behaviour.
    fn acquire(path: &str) -> ProcessLock {
        #[cfg(unix)]
        {
            if let Some(parent) = std::path::Path::new(path).parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let c_path = match std::ffi::CString::new(path) {
                Ok(value) => value,
                Err(_) => return ProcessLock { fd: -1 },
            };
            let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_CREAT | libc::O_RDWR, 0o600) };
            if fd < 0 {
                warn!(
                    "ProcessLock: open({}) failed ({}), continuing without cross-process lock",
                    path,
                    std::io::Error::last_os_error()
                );
                return ProcessLock { fd: -1 };
            }
            if unsafe { libc::flock(fd, libc::LOCK_EX) } != 0 {
                warn!(
                    "ProcessLock: flock({}) failed ({}), continuing without cross-process lock",
                    path,
                    std::io::Error::last_os_error()
                );
                unsafe { libc::close(fd) };
                return ProcessLock { fd: -1 };
            }
            debug!("ProcessLock: acquired exclusive lock {}", path);
            return ProcessLock { fd };
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            ProcessLock { fd: -1 }
        }
    }
}

impl Drop for ProcessLock {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            if self.fd >= 0 {
                unsafe {
                    libc::flock(self.fd, libc::LOCK_UN);
                    libc::close(self.fd);
                }
                debug!("ProcessLock: released");
            }
        }
        #[cfg(not(unix))]
        {
            let _ = self.fd;
        }
    }
}

/// Atomically write `data` to `path` via a per-pid temp file + rename().
///
/// rename() is atomic on the same filesystem, so no other process ever observes
/// a half-written file at the final path. When `readonly` is set the landed file
/// is chmod 0o444 (used for DEX, matching the previous behaviour).
fn atomic_write(path: &str, data: &[u8], readonly: bool) -> std::io::Result<()> {
    let tmp = format!("{}.{}.tmp", path, std::process::id());
    let _ = std::fs::remove_file(&tmp);
    {
        let mut file = File::create(&tmp)?;
        file.write_all(data)?;
        file.sync_all()?;
    }
    if readonly {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(metadata) = std::fs::metadata(&tmp) {
                let mut permissions = metadata.permissions();
                permissions.set_mode(0o444);
                let _ = std::fs::set_permissions(&tmp, permissions);
            }
        }
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn load_dex_core(
    env: &mut JNIEnv,
    cache_path: &str,
    data_path: &str,
    class_loader: &JObject,
    payload: &[(String, Vec<u8>)],
    sdk_int: jint,
) -> Result<(), Box<dyn std::error::Error>> {
    // Serialize all disk landing across processes. The lock is held only for
    // the file-writing phase and released before the per-process JNI
    // class-loader registration (which must run in every process).
    let (dex_paths, libs_dir, dex_opt_dir) = {
        let _land_lock = ProcessLock::acquire(&format!("{}/kapp_land.lock", cache_path));

        // 1. Extract assets (shared file) under the lock.
        extract_assets_core(data_path, payload)?;

        // 2. Land DEX + native libs atomically under the lock.
        // NOTE:
        // We intentionally use file-landing on all SDKs. In-memory mode can
        // trigger "Attempt to register dex file ... with multiple class
        // loaders" for some multi-process/provider startup sequences.
        if sdk_int >= 26 {
            info!(
                "load_dex_core: using file-landing mode on SDK {} for class-loader compatibility",
                sdk_int
            );
        }
        land_payload_files(cache_path, payload)?
    };

    // 3. Register the landed dex/native paths on THIS process's class loader.
    register_payload_on_loader(env, class_loader, &dex_paths, &libs_dir, &dex_opt_dir)
        .map_err(|e| e.into())
}

fn extract_assets_core(
    data_path: &str,
    payload: &[(String, Vec<u8>)],
) -> Result<(), Box<dyn std::error::Error>> {
    let zip_path = format!("{}/files/kapp_assets.zip", data_path);

    // Check if any assets exist in payload
    let asset_entries: Vec<_> = payload.iter().filter(|(name, _)| name.starts_with("assets/")).collect();
    if asset_entries.is_empty() {
        debug!("extract_assets_core: no assets in payload, skipping");
        return Ok(());
    }

    // Check if cache zip already exists with valid size
    let expected_data_size: u64 = asset_entries.iter().map(|(_, data)| data.len() as u64).sum();
    if let Ok(meta) = std::fs::metadata(&zip_path) {
        if meta.len() > 0 && meta.len() >= expected_data_size {
            info!("extract_assets_core: cache zip exists ({} bytes), skipping recreation", meta.len());
            return Ok(());
        }
    }

    debug!("extract_assets_core: Landing assets in {}", zip_path);
    
    // Ensure parent directory (files) exists
    if let Some(parent) = std::path::Path::new(&zip_path).parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Write to a temp file then rename() so a concurrent process never sees a
    // half-written assets zip. Runs under the load_dex_core cross-process lock.
    let tmp_zip_path = format!("{}.{}.tmp", zip_path, std::process::id());
    let _ = std::fs::remove_file(&tmp_zip_path);
    let file = File::create(&tmp_zip_path)?;
    let mut zip = zip::ZipWriter::new(file);
    let options = zip::write::FileOptions::default()
        .compression_method(zip::CompressionMethod::Stored); // Store uncompressed for speed/simplicity

    let mut asset_count = 0;
    for (name, data) in payload {
        if name.starts_with("assets/") {
            debug!("Adding asset to ZIP: {}", name);
            zip.start_file(name, options)?;
            zip.write_all(data)?;
            asset_count += 1;
        }
    }
    
    zip.finish()?;
    std::fs::rename(&tmp_zip_path, &zip_path)?;

    if asset_count > 0 {
        info!("Successfully packed {} protected assets into {}", asset_count, zip_path);
    }
    Ok(())
}

fn get_package_code_path(env: &mut JNIEnv, context: &JObject) -> Result<String, jni::errors::Error> {
    debug!("Calling getPackageCodePath...");
    let package_code_path = env
        .call_method(context, "getPackageCodePath", "()Ljava/lang/String;", &[])?
        .l()?;
    let path_str: String = env.get_string(&package_code_path.into())?.into();
    debug!("Package code path: {}", path_str);
    Ok(path_str)
}

fn read_cache_marker(cache_path: &str, apk_path: &str) -> Option<Vec<String>> {
    let marker_path = format!("{}/cache_marker", cache_path);
    let content = std::fs::read_to_string(&marker_path).ok()?;
    let mut lines = content.lines();
    let stored_apk = lines.next()?;
    if stored_apk != apk_path {
        debug!("Cache marker APK path mismatch, invalidating");
        return None;
    }
    let count: usize = lines.next()?.parse().ok()?;
    let mut names = Vec::with_capacity(count);
    for line in lines {
        if !line.is_empty() {
            names.push(line.to_string());
        }
    }
    if names.len() == count {
        info!("Cache marker valid: {} entries", count);
        Some(names)
    } else {
        debug!("Cache marker entry count mismatch: {} != {}", names.len(), count);
        None
    }
}

fn write_cache_marker(cache_path: &str, apk_path: &str, payload: &[(String, Vec<u8>)]) {
    let marker_path = format!("{}/cache_marker", cache_path);
    let mut content = format!("{}\n{}\n", apk_path, payload.len());
    for (name, _) in payload {
        content.push_str(name);
        content.push('\n');
    }
    if let Err(e) = std::fs::write(&marker_path, content) {
        warn!("Failed to write cache marker: {:?}", e);
    } else {
        info!("Cache marker written with {} entries", payload.len());
    }
}

fn validate_signature_hash(expected: &[u8; 32], actual: &[u8; 32]) -> Result<(), String> {
    if expected.iter().all(|&b| b == 0) {
        warn!("Signature hash check skipped (embedded hash is zero).");
        return Ok(());
    }

    if actual != expected {
        return Err(format!(
            "Signature mismatch! Expected: {}, Actual: {}",
            hex::encode(expected),
            hex::encode(actual)
        ));
    }

    Ok(())
}

fn extract_signature_bytes(
    env: &mut JNIEnv,
    package_info: &JObject,
) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
    if let Ok(signing_info_obj) = env
        .get_field(package_info, "signingInfo", "Landroid/content/pm/SigningInfo;")
        .and_then(|value| value.l())
    {
        if !signing_info_obj.is_null() {
            let signers_obj = env
                .call_method(
                    &signing_info_obj,
                    "getApkContentsSigners",
                    "()[Landroid/content/pm/Signature;",
                    &[],
                )?
                .l()?;
            if !signers_obj.is_null() {
                let signers_array: JObjectArray = signers_obj.into();
                if env.get_array_length(&signers_array)? > 0 {
                    let signature = env.get_object_array_element(&signers_array, 0)?;
                    let cert_bytes_j = env.call_method(&signature, "toByteArray", "()[B", &[])?.l()?;
                    let cert_bytes: Vec<u8> = env.convert_byte_array(&JByteArray::from(cert_bytes_j))?;
                    return Ok(Some(cert_bytes));
                }
            }
        }
    } else {
        let _ = env.exception_clear();
    }

    if let Ok(signatures_obj) = env
        .get_field(package_info, "signatures", "[Landroid/content/pm/Signature;")
        .and_then(|value| value.l())
    {
        // PackageInfo.signatures is only populated when the caller asked for
        // GET_SIGNATURES. A null array is therefore a "not requested" signal,
        // not a JNI error - GetArrayLength on it would abort the loader.
        if !signatures_obj.is_null() {
            let signatures_array: JObjectArray = signatures_obj.into();
            if env.get_array_length(&signatures_array)? > 0 {
                let signature = env.get_object_array_element(&signatures_array, 0)?;
                let cert_bytes_j = env.call_method(&signature, "toByteArray", "()[B", &[])?.l()?;
                let cert_bytes: Vec<u8> = env.convert_byte_array(&JByteArray::from(cert_bytes_j))?;
                return Ok(Some(cert_bytes));
            }
        }
    } else {
        let _ = env.exception_clear();
    }

    Ok(None)
}

fn get_package_info<'local>(
    env: &mut JNIEnv<'local>,
    pm: &JObject<'local>,
    package_name: &JObject<'local>,
    flags: i32,
) -> Result<JObject<'local>, jni::errors::Error> {
    env.call_method(
        pm,
        "getPackageInfo",
        "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;",
        &[package_name.into(), flags.into()],
    )?
    .l()
}

fn verify_integrity(
    env: &mut JNIEnv,
    context: &JObject,
) -> Result<(), Box<dyn std::error::Error>> {
    // Nothing to compare against: the packer embedded a zero hash (e.g. it was
    // started with --no-sign and no keystore). Skip the whole PackageManager
    // round-trip instead of failing on it - the comparison below is a no-op
    // anyway, and a failure here would silently stop the payload dex from ever
    // being loaded, killing the app with ClassNotFoundException at startup.
    if EXPECTED_SIGNATURE_HASH.iter().all(|&b| b == 0) {
        warn!("Signature hash check skipped (embedded hash is zero).");
        return Ok(());
    }

    info!("Verifying APK signature...");
    let package_name = env.call_method(context, "getPackageName", "()Ljava/lang/String;", &[])?.l()?;
    let pm = env.call_method(context, "getPackageManager", "()Landroid/content/pm/PackageManager;", &[])?.l()?;

    // Prefer modern flag first (API 28+), then fallback to legacy flag.
    const GET_SIGNING_CERTIFICATES: i32 = 0x08000000;
    const GET_SIGNATURES: i32 = 64;

    // On API 24-27 GET_SIGNING_CERTIFICATES is an unknown bit: getPackageInfo
    // still succeeds, but PackageInfo carries neither signingInfo nor
    // signatures. That must NOT be treated as a hard failure, otherwise the
    // shell aborts before loading the payload on every pre-Android 9 device.
    let mut cert_bytes: Option<Vec<u8>> = None;
    match get_package_info(env, &pm, &package_name, GET_SIGNING_CERTIFICATES) {
        Ok(package_info) => match extract_signature_bytes(env, &package_info) {
            Ok(bytes) => cert_bytes = bytes,
            Err(e) => {
                debug!("Reading SigningInfo failed, will retry with GET_SIGNATURES: {:?}", e);
                let _ = env.exception_clear();
            }
        },
        Err(e) => {
            debug!(
                "getPackageInfo(GET_SIGNING_CERTIFICATES) failed, will retry with GET_SIGNATURES: {:?}",
                e
            );
            let _ = env.exception_clear();
        }
    }

    if cert_bytes.is_none() {
        let package_info = get_package_info(env, &pm, &package_name, GET_SIGNATURES)?;
        cert_bytes = extract_signature_bytes(env, &package_info)?;
    }

    let cert_bytes = cert_bytes.ok_or("No signatures found in PackageInfo")?;

    let mut hasher = Sha256::new();
    hasher.update(&cert_bytes);
    let hash: [u8; 32] = hasher.finalize().into();

    validate_signature_hash(&EXPECTED_SIGNATURE_HASH, &hash)
        .map_err(Box::<dyn std::error::Error>::from)?;

    if EXPECTED_SIGNATURE_HASH.iter().any(|&b| b != 0) {
        info!("Signature integrity verified.");
    }

    Ok(())
}

fn extract_payload(path: &str, verify: bool) -> Result<Vec<(String, Vec<u8>)>, Box<dyn std::error::Error>> {
    debug!("{} {}", s!(strings_config::MSG_OPEN_APK).replace("{}", ""), path);
    let apk_file = File::open(path)?;
    let mut apk_zip = ZipArchive::new(apk_file)?;
    debug!("Opening content...");
    let mut payload_entry = apk_zip.by_name(&s!(strings_config::PAYLOAD_NAME))?;
    let mut encrypted_data = Vec::new();
    payload_entry.read_to_end(&mut encrypted_data)?;
    debug!("Read {} bytes from payload", encrypted_data.len());

    if verify {
        let mut hasher = Sha256::new();
        hasher.update(&encrypted_data);
        let hash = hasher.finalize();
        if hash.as_slice() != PAYLOAD_HASH {
            // Check if it's all zeros (empty/dummy config)
            if PAYLOAD_HASH != [0u8; 32] {
                error!("Payload hash mismatch! Expected: {}, Actual: {}", 
                    hex::encode(PAYLOAD_HASH), 
                    hex::encode(hash));
                return Err("Payload integrity check failed".into());
            } else {
                warn!("Payload hash check skipped (embedded hash is zero).");
            }
        }
    }

    decrypt_payload(&encrypted_data, &get_aes_key())
}

fn decrypt_payload(
    encrypted_data: &[u8],
    key: &[u8; 32],
) -> Result<Vec<(String, Vec<u8>)>, Box<dyn std::error::Error>> {
    let mut file = std::io::Cursor::new(encrypted_data);
    let file_len = encrypted_data.len() as u64;

    // Footer: [Metadata Size (4)] [Magic "SHELL" (5)]
    let footer_len = 9;
    if file_len < footer_len {
        return Err("Payload too small".into());
    }

    file.seek(SeekFrom::End(-(footer_len as i64)))?;
    let mut footer = [0u8; 9];
    file.read_exact(&mut footer)?;

    let magic = &footer[4..9];
    if magic != s!(strings_config::MAGIC_SHELL).as_bytes() {
        return Err(s!(strings_config::ERR_NO_PAYLOAD).into());
    }

    let metadata_size = u32::from_le_bytes(footer[0..4].try_into()?) as u64;
    
    // Metadata Block: [N (4)] + [ [NameLen(2)] [Name] [Size(4)] [IV(12)] ] * N
    let metadata_start = file_len
        .checked_sub(footer_len as u64)
        .and_then(|v| v.checked_sub(metadata_size))
        .ok_or("Invalid metadata size")?;

    file.seek(SeekFrom::Start(metadata_start))?;
    let mut metadata = vec![0u8; metadata_size as usize];
    file.read_exact(&mut metadata)?;

    let mut cursor = std::io::Cursor::new(&metadata);
    let mut n_bytes = [0u8; 4];
    cursor.read_exact(&mut n_bytes)?;
    let num_files = u32::from_le_bytes(n_bytes);

    let mut entries = Vec::new();
    let mut total_encrypted_size = 0;

    for _ in 0..num_files {
        let mut name_len_bytes = [0u8; 2];
        cursor.read_exact(&mut name_len_bytes)?;
        let name_len = u16::from_le_bytes(name_len_bytes) as usize;
        
        let mut name_bytes = vec![0u8; name_len];
        cursor.read_exact(&mut name_bytes)?;
        let name = String::from_utf8(name_bytes)?;

        let mut size_bytes = [0u8; 4];
        cursor.read_exact(&mut size_bytes)?;
        let size = u32::from_le_bytes(size_bytes);
        
        let mut iv = [0u8; 12];
        cursor.read_exact(&mut iv)?;
        
        entries.push((name, size, iv));
        total_encrypted_size += size as u64;
    }

    // Read Payloads
    let payload_start = metadata_start
        .checked_sub(total_encrypted_size)
        .ok_or("Invalid payload offset")?;

    file.seek(SeekFrom::Start(payload_start))?;
    
    let cipher = Aes256Gcm::new(key.into());
    let mut results = Vec::new();

    for (name, size, iv) in entries {
        let mut enc_buf = vec![0u8; size as usize];
        file.read_exact(&mut enc_buf)?;
        
        let nonce = Nonce::from_slice(&iv);
        let plaintext = cipher.decrypt(nonce, enc_buf.as_ref())
            .map_err(|e| format!("Decryption failed for {}: {:?}", name, e))?;
        
        results.push((name, plaintext));
    }
    
    Ok(results)
}

#[allow(dead_code)]
fn load_in_memory(env: &mut JNIEnv, cache_path: &str, target_loader: &JObject, file_list: &[(String, Vec<u8>)]) -> Result<(), jni::errors::Error> {
    info!("load_in_memory called with {} items", file_list.len());
    // 1. Separate DEXs and Libs
    let mut dex_buffers = Vec::new();
    let mut lib_buffers = Vec::new();
    let current_abi = get_current_abi();
    debug!("Current ABI: {}", current_abi);

    let lib_prefix = format!("lib/{}/", current_abi);

    for (name, data) in file_list {
        if name.ends_with(".dex") {
             dex_buffers.push(data);
        } else if name.starts_with(&lib_prefix) && name.ends_with(".so") {
             let filename = name.strip_prefix(&lib_prefix).unwrap_or(name);
             lib_buffers.push((filename, data));
        }
    }

    debug!("Found {} DEXs and {} Libs for current ABI", dex_buffers.len(), lib_buffers.len());

    // 2. Extract Libs to Cache
    debug!("Extracting libs to cache...");
    let libs_dir = format!("{}/native_libs", cache_path);
    std::fs::create_dir_all(&libs_dir).unwrap_or(());

    for (filename, data) in lib_buffers {
        let lib_path = format!("{}/{}", libs_dir, filename);
        debug!("Writing lib: {}", lib_path);
        if let Ok(mut file) = File::create(&lib_path) {
            let _ = file.write_all(data);
        }
    }

    // 3. Create ByteBuffer[] for DEXs
    if dex_buffers.is_empty() {
        warn!("No DEX files to load in memory!");
        return Ok(());
    }

    debug!("Creating ByteBuffer array for {} DEXs...", dex_buffers.len());
    let byte_buffer_cls = env.find_class("java/nio/ByteBuffer")?;
    let buffer_array = env.new_object_array(dex_buffers.len() as i32, &byte_buffer_cls, JObject::null())?;

    for (i, dex_data) in dex_buffers.iter().enumerate() {
        debug!("Wrapping DEX {} ({} bytes)...", i, dex_data.len());
        let byte_array = env.byte_array_from_slice(dex_data)?;
        let buffer = env.call_static_method(
            &byte_buffer_cls,
            "wrap", 
            "([B)Ljava/nio/ByteBuffer;", 
            &[JValue::Object(&byte_array.into())]
        )?.l()?;
        
        env.set_object_array_element(&buffer_array, i as i32, buffer)?;
    }

    // 4. Create InMemoryDexClassLoader
    debug!("Instantiating InMemoryDexClassLoader...");

    let dex_loader_cls = env.find_class("dalvik/system/InMemoryDexClassLoader")?;
    let buffer_array_obj: JObject = buffer_array.into();

    let ctor_sig_with_lib = "([Ljava/nio/ByteBuffer;Ljava/lang/String;Ljava/lang/ClassLoader;)V";
    
    let libs_dir_j = env.new_string(&libs_dir)?;
    let libs_dir_obj: JObject = libs_dir_j.into();
    
    let loader_res = env.new_object(
        &dex_loader_cls,
        ctor_sig_with_lib,
        &[
            JValue::Object(&buffer_array_obj),
            JValue::Object(&libs_dir_obj),
            JValue::Object(target_loader)
        ]
    );

    let loader = match loader_res {
        Ok(l) => l,
        Err(_) => {
            let _ = env.exception_clear();
            env.new_object(
                &dex_loader_cls,
                "([Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V",
                &[JValue::Object(&buffer_array_obj), JValue::Object(target_loader)]
            )?
        }
    };

    // 5. Inject Dex Elements into Parent Loader (Hotfix style)
    inject_dex_elements(env, &loader, target_loader)?;
    
    info!("load_in_memory: Completion successful");
    Ok(())
}

fn try_add_dex_path(env: &mut JNIEnv, target_loader: &JObject, joined_paths: &str) -> bool {
    let dex_path_j = match env.new_string(joined_paths) {
        Ok(value) => value,
        Err(_) => return false,
    };
    let dex_path_obj: JObject = dex_path_j.into();

    let with_bool = env.call_method(
        target_loader,
        "addDexPath",
        "(Ljava/lang/String;Z)V",
        &[JValue::Object(&dex_path_obj), JValue::Bool(0)],
    );
    if with_bool.is_ok() {
        return true;
    }
    let _ = env.exception_clear();

    let plain = env.call_method(
        target_loader,
        "addDexPath",
        "(Ljava/lang/String;)V",
        &[JValue::Object(&dex_path_obj)],
    );
    if plain.is_ok() {
        return true;
    }
    let _ = env.exception_clear();
    false
}

fn try_add_native_path(env: &mut JNIEnv, target_loader: &JObject, libs_dir: &str) -> bool {
    let libs_dir_j = match env.new_string(libs_dir) {
        Ok(value) => value,
        Err(_) => return false,
    };
    let libs_dir_obj: JObject = libs_dir_j.into();

    let array_list_cls = match env.find_class("java/util/ArrayList") {
        Ok(value) => value,
        Err(_) => {
            let _ = env.exception_clear();
            return false;
        }
    };
    let native_paths = match env.new_object(&array_list_cls, "()V", &[]) {
        Ok(value) => value,
        Err(_) => {
            let _ = env.exception_clear();
            return false;
        }
    };
    let add_result = env.call_method(
        &native_paths,
        "add",
        "(Ljava/lang/Object;)Z",
        &[JValue::Object(&libs_dir_obj)],
    );
    if add_result.is_err() {
        let _ = env.exception_clear();
        return false;
    }

    let result = env.call_method(
        target_loader,
        "addNativePath",
        "(Ljava/util/Collection;)V",
        &[JValue::Object(&native_paths)],
    );
    if result.is_ok() {
        return true;
    }
    let _ = env.exception_clear();
    false
}

fn create_helper_dex_loader<'local>(
    env: &mut JNIEnv<'local>,
    target_loader: &JObject,
    dex_paths: &str,
    optimized_dir: Option<&str>,
    libs_dir: &str,
) -> Result<JObject<'local>, jni::errors::Error> {
    let dex_loader_cls = env.find_class("dalvik/system/DexClassLoader")?;

    let dex_path_j = env.new_string(dex_paths)?;
    let dex_path_obj: JObject = dex_path_j.into();

    let opt_obj = match optimized_dir {
        Some(dir) => {
            std::fs::create_dir_all(dir).unwrap_or(());
            let opt_dir_j = env.new_string(dir)?;
            let obj: JObject = opt_dir_j.into();
            obj
        }
        None => JObject::null(),
    };

    let libs_dir_j = env.new_string(libs_dir)?;
    let libs_dir_obj: JObject = libs_dir_j.into();

    env.new_object(
        &dex_loader_cls,
        "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/ClassLoader;)V",
        &[
            JValue::Object(&dex_path_obj),
            JValue::Object(&opt_obj),
            JValue::Object(&libs_dir_obj),
            JValue::Object(target_loader),
        ],
    )
}

fn inject_dex_via_helper_loader(
    env: &mut JNIEnv,
    target_loader: &JObject,
    joined_dex_paths: &str,
    libs_dir: &str,
    dex_opt_dir: &str,
) -> Result<(), jni::errors::Error> {
    // The helper loader is the only loader opening these dex files, so the
    // ART "multiple class loaders" dex registration conflict cannot happen.
    let helper = create_helper_dex_loader(
        env,
        target_loader,
        joined_dex_paths,
        Some(dex_opt_dir),
        libs_dir,
    )?;

    inject_dex_elements(env, &helper, target_loader)?;
    // Old platforms without addDexPath also lack addNativePath; harvest both
    // element arrays from the same helper loader.
    inject_native_dir_from_loader(env, &helper, target_loader, libs_dir)
}

fn inject_native_lib_dir(
    env: &mut JNIEnv,
    target_loader: &JObject,
    libs_dir: &str,
) -> Result<(), jni::errors::Error> {
    // No dex files on this helper loader: it exists purely to obtain a
    // correctly constructed DexPathList$Element for libs_dir on the current
    // platform version.
    let helper = create_helper_dex_loader(env, target_loader, "", None, libs_dir)?;
    inject_native_dir_from_loader(env, &helper, target_loader, libs_dir)
}

fn inject_native_dir_from_loader(
    env: &mut JNIEnv,
    source_loader: &JObject,
    target_loader: &JObject,
    libs_dir: &str,
) -> Result<(), jni::errors::Error> {
    let source_path_list = env
        .get_field(source_loader, "pathList", "Ldalvik/system/DexPathList;")?
        .l()?;
    let target_path_list = env
        .get_field(target_loader, "pathList", "Ldalvik/system/DexPathList;")?
        .l()?;

    let source_elems_obj = env
        .get_field(
            &source_path_list,
            "nativeLibraryPathElements",
            "[Ldalvik/system/DexPathList$Element;",
        )?
        .l()?;
    let source_array: JObjectArray = source_elems_obj.into();
    let source_len = env.get_array_length(&source_array)?;

    // Only harvest the Element for libs_dir; the helper loader also lists
    // system library dirs the target loader already knows about.
    let mut matched: Vec<JObject> = Vec::new();
    for i in 0..source_len {
        let elem = env.get_object_array_element(&source_array, i)?;
        if let Some(path) = get_element_path(env, &elem) {
            if path == libs_dir {
                matched.push(elem);
            }
        }
    }

    if matched.is_empty() {
        warn!(
            "inject_native_dir_from_loader: no native lib element found for {}",
            libs_dir
        );
        return Ok(());
    }

    let target_elems_obj = env
        .get_field(
            &target_path_list,
            "nativeLibraryPathElements",
            "[Ldalvik/system/DexPathList$Element;",
        )?
        .l()?;
    let target_array: JObjectArray = target_elems_obj.into();
    let target_len = env.get_array_length(&target_array)?;

    let element_cls = env.find_class("dalvik/system/DexPathList$Element")?;
    let total_len = target_len + matched.len() as i32;
    let new_array = env.new_object_array(total_len, &element_cls, JObject::null())?;

    for i in 0..target_len {
        let elem = env.get_object_array_element(&target_array, i)?;
        env.set_object_array_element(&new_array, i, elem)?;
    }

    for (idx, elem) in matched.into_iter().enumerate() {
        env.set_object_array_element(&new_array, target_len + idx as i32, elem)?;
    }

    let new_array_obj = JObject::from(new_array);
    env.set_field(
        &target_path_list,
        "nativeLibraryPathElements",
        "[Ldalvik/system/DexPathList$Element;",
        JValue::Object(&new_array_obj),
    )?;

    // DexPathList.addNativePath() keeps two fields in sync; mirror that. See
    // add_native_library_directory for why the second one matters.
    add_native_library_directory(env, &target_path_list, libs_dir);

    info!(
        "inject_native_dir_from_loader: registered {} into native library path",
        libs_dir
    );
    Ok(())
}

/// Companion to the nativeLibraryPathElements injection: also append `libs_dir`
/// to DexPathList.nativeLibraryDirectories.
///
/// The framework's own DexPathList.addNativePath() updates BOTH fields. The
/// Element array drives findLibrary() (name -> absolute path), while the List
/// drives BaseDexClassLoader.getLdLibraryPath(), which is the value libnativeloader
/// hands to android_create_namespace() as the namespace's ld_library_path. Only
/// patching the Elements therefore leaves any namespace created after this point
/// (a child loader, a plugin framework, a WebView-style provider) searching a
/// stale path in which the payload libraries no longer exist.
///
/// Purely best-effort: the field is private, may be absent on OEM builds and may
/// hold an immutable List, none of which must stop the loader.
fn add_native_library_directory(env: &mut JNIEnv, path_list: &JObject, libs_dir: &str) {
    let dirs_obj = match env
        .get_field(path_list, "nativeLibraryDirectories", "Ljava/util/List;")
        .and_then(|value| value.l())
    {
        Ok(value) if !value.is_null() => value,
        _ => {
            let _ = env.exception_clear();
            debug!("add_native_library_directory: nativeLibraryDirectories unavailable");
            return;
        }
    };

    let file_cls = match env.find_class("java/io/File") {
        Ok(cls) => cls,
        Err(e) => {
            let _ = env.exception_clear();
            warn!("add_native_library_directory: cannot resolve java/io/File: {:?}", e);
            return;
        }
    };

    let dir_str = match env.new_string(libs_dir) {
        Ok(s) => s,
        Err(e) => {
            let _ = env.exception_clear();
            warn!("add_native_library_directory: new_string failed: {:?}", e);
            return;
        }
    };
    let dir_str_obj = JObject::from(dir_str);

    let file = match env.new_object(
        &file_cls,
        "(Ljava/lang/String;)V",
        &[JValue::Object(&dir_str_obj)],
    ) {
        Ok(f) => f,
        Err(e) => {
            let _ = env.exception_clear();
            warn!("add_native_library_directory: new File failed: {:?}", e);
            return;
        }
    };

    // File.equals compares paths, so this is a real duplicate check - the
    // loader may already know about libs_dir through addNativePath().
    // JValueGen::z() consumes its receiver, so the flag has to be read outside
    // the match: a pattern guard may only borrow the binding it tests.
    let already_present = match env.call_method(
        &dirs_obj,
        "contains",
        "(Ljava/lang/Object;)Z",
        &[JValue::Object(&file)],
    ) {
        Ok(value) => value.z().unwrap_or(false),
        Err(e) => {
            let _ = env.exception_clear();
            warn!("add_native_library_directory: contains failed: {:?}", e);
            return;
        }
    };
    if already_present {
        return;
    }

    match env.call_method(
        &dirs_obj,
        "add",
        "(Ljava/lang/Object;)Z",
        &[JValue::Object(&file)],
    ) {
        Ok(_) => info!(
            "add_native_library_directory: added {} to nativeLibraryDirectories",
            libs_dir
        ),
        Err(e) => {
            let _ = env.exception_clear();
            warn!(
                "add_native_library_directory: cannot extend nativeLibraryDirectories: {:?}",
                e
            );
        }
    }
}

/// List every .so inside `libs_dir`, sorted so the load order is reproducible.
fn collect_so_paths(libs_dir: &str) -> Vec<String> {
    let dir = match std::fs::read_dir(libs_dir) {
        Ok(d) => d,
        Err(e) => {
            warn!("collect_so_paths: cannot read {}: {}", libs_dir, e);
            return Vec::new();
        }
    };

    let mut so_paths: Vec<String> = Vec::new();
    for entry in dir.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("so") {
            if let Some(p) = path.to_str() {
                so_paths.push(p.to_string());
            }
        }
    }
    so_paths.sort();
    so_paths
}

/// System.load() the paths through com.kapp.shell.NativeLibLoader.
///
/// Calling System.load straight from JNI makes Runtime.load0 resolve the owning
/// loader with Reflection.getCallerClass(), which does not reliably yield the
/// app's PathClassLoader when the caller is native code. ART then registers the
/// library against the wrong loader, and since FindCodeForNativeMethod only
/// searches the libraries owned by the *declaring* class's loader, every native
/// method of the payload keeps failing with "No implementation found". Routing
/// the call through a bootstrap-dex class pins the ownership.
///
/// Returns the number of paths the helper could not load.
fn load_paths_via_java(env: &mut JNIEnv, paths: &[String]) -> Result<i32, jni::errors::Error> {
    if paths.is_empty() {
        return Ok(0);
    }

    let loader_cls = env.find_class("com/kapp/shell/NativeLibLoader")?;
    let string_cls = env.find_class("java/lang/String")?;
    let array = env.new_object_array(paths.len() as i32, &string_cls, JObject::null())?;
    for (idx, path) in paths.iter().enumerate() {
        let jpath = env.new_string(path)?;
        env.set_object_array_element(&array, idx as i32, jpath)?;
    }

    let array_obj = JObject::from(array);
    env.call_static_method(
        &loader_cls,
        "loadInOrder",
        "([Ljava/lang/String;)I",
        &[JValue::Object(&array_obj)],
    )?
    .i()
}

/// Third fallback for native lib registration: directly System.load() each
/// .so file from `libs_dir`. This works on any platform (including OEM-modified
/// ART where DexPathList fields are missing/renamed) because it bypasses
/// classloader internals entirely. Pre-loading a .so makes it available to
/// subsequent System.loadLibrary() calls from the original app.
fn preload_native_libs_direct(
    env: &mut JNIEnv,
    libs_dir: &str,
) -> Result<(), jni::errors::Error> {
    let so_paths = collect_so_paths(libs_dir);
    if so_paths.is_empty() {
        return Ok(());
    }

    let failures = load_paths_via_java(env, &so_paths)?;
    info!(
        "preload_native_libs_direct: pre-loaded {}/{} .so files from {}",
        so_paths.len().saturating_sub(failures as usize),
        so_paths.len(),
        libs_dir
    );
    Ok(())
}

#[derive(Debug)]
struct ElfDeps {
    soname: String,
    needed: Vec<String>,
}

fn elf_u16(data: &[u8], off: usize, le: bool) -> Option<u16> {
    let b = data.get(off..off + 2)?;
    Some(if le {
        u16::from_le_bytes([b[0], b[1]])
    } else {
        u16::from_be_bytes([b[0], b[1]])
    })
}

fn elf_u32(data: &[u8], off: usize, le: bool) -> Option<u32> {
    let b = data.get(off..off + 4)?;
    Some(if le {
        u32::from_le_bytes([b[0], b[1], b[2], b[3]])
    } else {
        u32::from_be_bytes([b[0], b[1], b[2], b[3]])
    })
}

fn elf_u64(data: &[u8], off: usize, le: bool) -> Option<u64> {
    let b = data.get(off..off + 8)?;
    let mut raw = [0u8; 8];
    raw.copy_from_slice(b);
    Some(if le {
        u64::from_le_bytes(raw)
    } else {
        u64::from_be_bytes(raw)
    })
}

/// Fill `buf` from the file's current position and report how many bytes were
/// actually read. A short read is not an error: callers parse what they got.
fn read_up_to(file: &mut File, buf: &mut [u8]) -> Option<usize> {
    let mut total = 0;
    while total < buf.len() {
        match file.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    Some(total)
}

/// Read DT_SONAME and the DT_NEEDED list out of an ELF file.
///
/// Hand-rolled on purpose: this runs on every startup for a handful of decrypted
/// .so files, and pulling in a parsing crate would grow libshell.so (and its own
/// dependency closure) for no benefit. Only the header, the program headers, the
/// dynamic section and the dynamic string table are read - the payload libraries
/// here run into tens of megabytes, so slurping them whole would be a needless
/// allocation on 32-bit devices. Anything that is not a readable, well-formed ELF
/// yields None so the caller can skip it.
fn read_elf_deps(path: &str) -> Option<ElfDeps> {
    let mut file = File::open(path).ok()?;

    // 64 bytes covers both the ELF32 and the ELF64 header layout.
    let mut ehdr = [0u8; 64];
    if file.read_exact(&mut ehdr).is_err() {
        return None;
    }
    if &ehdr[0..4] != b"\x7fELF" {
        return None;
    }
    let is64 = ehdr[4] == 2;
    let le = ehdr[5] != 2;

    let (phoff, phentsize, phnum) = if is64 {
        (
            elf_u64(&ehdr, 0x20, le)?,
            elf_u16(&ehdr, 0x36, le)? as usize,
            elf_u16(&ehdr, 0x38, le)? as usize,
        )
    } else {
        (
            elf_u32(&ehdr, 0x1c, le)? as u64,
            elf_u16(&ehdr, 0x2a, le)? as usize,
            elf_u16(&ehdr, 0x2c, le)? as usize,
        )
    };

    // Sanity caps: keep the allocation and index arithmetic below bounded even
    // when the header is garbage. Real files have a handful of segments.
    if phentsize < 32 || phentsize > 512 || phnum == 0 || phnum > 512 {
        return None;
    }

    let mut phdrs = vec![0u8; phnum * phentsize];
    file.seek(SeekFrom::Start(phoff)).ok()?;
    file.read_exact(&mut phdrs).ok()?;

    let mut loads: Vec<(u64, u64, u64)> = Vec::new();
    let mut dyn_seg: Option<(u64, u64)> = None;

    for i in 0..phnum {
        let base = i * phentsize;
        let p_type = elf_u32(&phdrs, base, le)?;
        let (p_offset, p_vaddr, p_filesz) = if is64 {
            (
                elf_u64(&phdrs, base + 8, le)?,
                elf_u64(&phdrs, base + 16, le)?,
                elf_u64(&phdrs, base + 32, le)?,
            )
        } else {
            (
                elf_u32(&phdrs, base + 4, le)? as u64,
                elf_u32(&phdrs, base + 8, le)? as u64,
                elf_u32(&phdrs, base + 16, le)? as u64,
            )
        };
        if p_type == 1 {
            // PT_LOAD: remembered so DT_STRTAB's virtual address can be turned
            // back into an offset inside this file.
            loads.push((p_vaddr, p_offset, p_filesz));
        } else if p_type == 2 {
            dyn_seg = Some((p_offset, p_filesz));
        }
    }

    let (dyn_off, dyn_size) = dyn_seg?;
    // A shared library carries a few hundred dynamic entries at most.
    let dyn_len = dyn_size.min(1 << 20) as usize;
    if dyn_len == 0 {
        return None;
    }
    let mut dynamic = vec![0u8; dyn_len];
    file.seek(SeekFrom::Start(dyn_off)).ok()?;
    let dyn_len = read_up_to(&mut file, &mut dynamic)?;

    const DT_NULL: u64 = 0;
    const DT_NEEDED: u64 = 1;
    const DT_STRTAB: u64 = 5;
    const DT_STRSZ: u64 = 10;
    const DT_SONAME: u64 = 14;

    let entry_size: usize = if is64 { 16 } else { 8 };
    let mut strtab_va: u64 = 0;
    let mut strtab_size: u64 = 0;
    let mut soname_off: Option<u64> = None;
    let mut needed_offs: Vec<u64> = Vec::new();

    let mut off = 0usize;
    while off + entry_size <= dyn_len {
        let (tag, val) = if is64 {
            (elf_u64(&dynamic, off, le)?, elf_u64(&dynamic, off + 8, le)?)
        } else {
            (
                elf_u32(&dynamic, off, le)? as u64,
                elf_u32(&dynamic, off + 4, le)? as u64,
            )
        };
        match tag {
            DT_NULL => break,
            DT_NEEDED => needed_offs.push(val),
            DT_STRTAB => strtab_va = val,
            DT_STRSZ => strtab_size = val,
            DT_SONAME => soname_off = Some(val),
            _ => {}
        }
        off += entry_size;
    }

    let strtab_off = loads.iter().find_map(|&(vaddr, file_off, filesz)| {
        if strtab_va >= vaddr && strtab_va < vaddr + filesz {
            Some(strtab_va - vaddr + file_off)
        } else {
            None
        }
    })?;

    let strtab_len = strtab_size.min(1 << 20) as usize;
    if strtab_len == 0 {
        return None;
    }
    let mut strtab = vec![0u8; strtab_len];
    file.seek(SeekFrom::Start(strtab_off)).ok()?;
    let strtab_len = read_up_to(&mut file, &mut strtab)?;

    let read_str = |str_off: u64| -> Option<String> {
        if str_off >= strtab_len as u64 {
            return None;
        }
        let bytes = strtab.get(str_off as usize..strtab_len)?;
        let end = bytes.iter().position(|&b| b == 0)?;
        String::from_utf8(bytes[..end].to_vec()).ok()
    };

    Some(ElfDeps {
        soname: soname_off.and_then(|o| read_str(o)).unwrap_or_default(),
        needed: needed_offs.iter().filter_map(|o| read_str(*o)).collect(),
    })
}

/// Post-order DFS over the DT_NEEDED graph, so every library ends up in
/// `ordered` before the libraries that need it. The visited set doubles as cycle
/// protection - real .so files do contain DT_NEEDED back-edges.
fn visit_native_deps(
    path: &str,
    needed: &HashMap<String, Vec<String>>,
    visited: &mut HashSet<String>,
    ordered: &mut Vec<String>,
) {
    if !visited.insert(path.to_string()) {
        return;
    }
    if let Some(deps) = needed.get(path) {
        for dep in deps {
            visit_native_deps(dep, needed, visited, ordered);
        }
    }
    ordered.push(path.to_string());
}

/// Pre-load the payload libraries that another payload library depends on.
///
/// This is NOT redundant with the classloader patching above, and it is the
/// reason a hardened build can fail with "No implementation found" while the
/// unhardened one works:
///
/// On API 24+ every app ClassLoader gets an isolated linker namespace whose
/// ld_library_path is snapshotted from BaseDexClassLoader.getLdLibraryPath() the
/// first time a library is loaded through it - here, ShellApplication's static
/// block loading libshell.so, long before the payload is decrypted. Patching
/// DexPathList afterwards cannot un-freeze it. So when the linker later resolves
/// libbdface_sdk.so's DT_NEEDED entries it searches only (a) libraries already
/// loaded in the namespace and (b) that stale path, from which the packer has
/// stripped every app-supplied .so. dlopen fails, the SDK swallows the
/// UnsatisfiedLinkError in its own static initializer, and every native method
/// of the SDK then reports "No implementation found".
///
/// Pre-loading the dependencies satisfies (a).
///
/// Only libraries that a sibling actually DT_NEEDEDs are loaded. Force-loading
/// everything would be wrong here: a payload may carry two files sharing one
/// SONAME (a vendor-renamed variant), and loading the wrong one first shadows
/// the right one for the whole process.
fn preload_shared_native_deps(env: &mut JNIEnv, libs_dir: &str) -> Result<(), jni::errors::Error> {
    let so_paths = collect_so_paths(libs_dir);
    if so_paths.len() < 2 {
        return Ok(());
    }

    let mut parsed: Vec<(String, ElfDeps)> = Vec::new();
    for path in &so_paths {
        match read_elf_deps(path) {
            Some(deps) => parsed.push((path.clone(), deps)),
            None => debug!("preload_shared_native_deps: not a parsable ELF: {}", path),
        }
    }
    if parsed.is_empty() {
        return Ok(());
    }

    // soname -> path. File names are inserted first and DT_SONAME only fills the
    // gaps, because that is what the linker does: it looks for a file with that
    // name. This keeps a renamed variant (libdk_serial_port.so carrying SONAME
    // libserial_port.so) from hijacking lookups for the real libserial_port.so.
    let mut by_soname: HashMap<String, String> = HashMap::new();
    for (path, _) in &parsed {
        if let Some(name) = path.rsplit('/').next() {
            by_soname.insert(name.to_string(), path.clone());
        }
    }
    for (path, deps) in &parsed {
        if !deps.soname.is_empty() {
            by_soname
                .entry(deps.soname.clone())
                .or_insert_with(|| path.clone());
        }
    }

    // Reduce DT_NEEDED sonames to the payload paths they resolve to.
    let mut needed_by_path: HashMap<String, Vec<String>> = HashMap::new();
    let mut required: Vec<String> = Vec::new();
    for (path, deps) in &parsed {
        let mut resolved: Vec<String> = Vec::new();
        for soname in &deps.needed {
            if let Some(dep) = by_soname.get(soname) {
                if dep != path {
                    resolved.push(dep.clone());
                    required.push(dep.clone());
                }
            }
        }
        needed_by_path.insert(path.clone(), resolved);
    }

    required.sort();
    required.dedup();
    if required.is_empty() {
        debug!(
            "preload_shared_native_deps: no intra-payload native dependencies in {}",
            libs_dir
        );
        return Ok(());
    }

    let mut ordered: Vec<String> = Vec::new();
    let mut visited: HashSet<String> = HashSet::new();
    for path in &required {
        visit_native_deps(path, &needed_by_path, &mut visited, &mut ordered);
    }

    debug!(
        "preload_shared_native_deps: dependency order for {}: {:?}",
        libs_dir, ordered
    );

    let failures = load_paths_via_java(env, &ordered)?;
    info!(
        "preload_shared_native_deps: pre-loaded {}/{} shared native dependencies from {}",
        ordered.len().saturating_sub(failures as usize),
        ordered.len(),
        libs_dir
    );
    Ok(())
}

fn get_element_path(env: &mut JNIEnv, element: &JObject) -> Option<String> {
    // The field was renamed from "file" to "path" across platform releases.
    for field_name in ["path", "file"] {
        let field = match env.get_field(element, field_name, "Ljava/io/File;") {
            Ok(value) => value,
            Err(_) => {
                let _ = env.exception_clear();
                continue;
            }
        };
        let file_obj = match field.l() {
            Ok(value) => value,
            Err(_) => {
                let _ = env.exception_clear();
                continue;
            }
        };
        if file_obj.is_null() {
            continue;
        }
        let abs_path = match env.call_method(
            &file_obj,
            "getAbsolutePath",
            "()Ljava/lang/String;",
            &[],
        ) {
            Ok(value) => value,
            Err(_) => {
                let _ = env.exception_clear();
                continue;
            }
        };
        let abs_obj = match abs_path.l() {
            Ok(value) => value,
            Err(_) => {
                let _ = env.exception_clear();
                continue;
            }
        };
        if let Ok(path) = env.get_string(&JString::from(abs_obj)) {
            return Some(path.into());
        }
        let _ = env.exception_clear();
    }
    None
}

fn get_current_abi() -> &'static str {
    #[cfg(target_arch = "aarch64")]
    return "arm64-v8a";
    #[cfg(target_arch = "arm")]
    return "armeabi-v7a";
    #[cfg(target_arch = "x86")]
    return "x86";
    #[cfg(target_arch = "x86_64")]
    return "x86_64";
    #[cfg(not(any(target_arch = "aarch64", target_arch = "arm", target_arch = "x86", target_arch = "x86_64")))]
    return "unknown";
}

fn is_cache_valid(cache_path: &str, data_path: &str, file_list: &[(String, Vec<u8>)]) -> bool {
    let dex_cache_dir = format!("{}/dex_landing", cache_path);
    let libs_dir = format!("{}/native_libs", cache_path);
    let current_abi = get_current_abi();
    let lib_prefix = format!("lib/{}/", current_abi);

    let mut dex_count = 0;
    let mut lib_count = 0;

    for (i, (name, data)) in file_list.iter().enumerate() {
        if name.ends_with(".dex") {
            let dex_path = format!("{}/payload_{}.dex", dex_cache_dir, i);
            match std::fs::metadata(&dex_path) {
                // When data is empty (from cache marker) require a non-zero
                // file: a zero-byte artifact means a previous landing was
                // interrupted and must be re-extracted.
                Ok(meta) if (data.is_empty() && meta.len() > 0) || meta.len() == data.len() as u64 => {}
                _ => {
                    debug!("Cache miss: DEX {} missing or size mismatch", dex_path);
                    return false;
                }
            }
            dex_count += 1;
        } else if name.starts_with(&lib_prefix) && name.ends_with(".so") {
            let filename = name.strip_prefix(&lib_prefix).unwrap_or(name);
            let lib_path = format!("{}/{}", libs_dir, filename);
            match std::fs::metadata(&lib_path) {
                Ok(meta) if (data.is_empty() && meta.len() > 0) || meta.len() == data.len() as u64 => {}
                _ => {
                    debug!("Cache miss: SO {} missing or size mismatch", lib_path);
                    return false;
                }
            }
            lib_count += 1;
        }
    }

    if dex_count == 0 {
        debug!("Cache miss: no DEX files in payload");
        return false;
    }

    // Check assets zip (only when data_path is provided)
    if !data_path.is_empty() {
        let zip_path = format!("{}/files/kapp_assets.zip", data_path);
        let has_assets = file_list.iter().any(|(name, _)| name.starts_with("assets/"));
        if has_assets {
            match std::fs::metadata(&zip_path) {
                Ok(meta) if meta.len() > 0 => {}
                _ => {
                    debug!("Cache miss: assets zip missing or empty");
                    return false;
                }
            }
        }
    }

    info!("Cache valid: {} DEXs, {} SOs", dex_count, lib_count);
    true
}

fn land_payload_files(
    cache_path: &str,
    file_list: &[(String, Vec<u8>)],
) -> Result<(Vec<String>, String, String), Box<dyn std::error::Error>> {
    let dex_cache_dir = format!("{}/dex_landing", cache_path);
    std::fs::create_dir_all(&dex_cache_dir).unwrap_or(());

    // API 24/25 still honour DexClassLoader's optimizedDirectory, and ART
    // derives the oat output path as "<optimizedDirectory>/<dexFileName>".
    // Handing it the landing directory itself therefore makes the oat path
    // identical to the source dex (which is chmod 0444), so dex2oat fails, the
    // DexPathList$Element keeps a null DexFile and every payload class goes
    // missing at startup. Keep the optimized output in its own directory.
    let dex_opt_dir = format!("{}/dex_opt", cache_path);
    std::fs::create_dir_all(&dex_opt_dir).unwrap_or(());

    let libs_dir = format!("{}/native_libs", cache_path);
    std::fs::create_dir_all(&libs_dir).unwrap_or(());

    let mut dex_paths = Vec::new();

    // Extract files (skip if cache is valid). Runs under the load_dex_core
    // cross-process lock, so this double-check is race-free: the process that
    // lands first wins, the rest see a valid cache and only rebuild the paths.
    let current_abi = get_current_abi();
    let lib_prefix = format!("lib/{}/", current_abi);
    let cache_ok = is_cache_valid(cache_path, "", file_list);

    if cache_ok {
        info!("land_payload_files: cache is valid, skipping file extraction");
    }

    for (i, (name, data)) in file_list.iter().enumerate() {
        if name.ends_with(".dex") {
            let dex_path = format!("{}/payload_{}.dex", dex_cache_dir, i);
            // Never write on the empty-data fast path; only land real bytes,
            // and do so atomically so no process observes a partial file.
            if !cache_ok && !data.is_empty() {
                if let Err(e) = atomic_write(&dex_path, data, true) {
                    error!("land_payload_files: failed to write dex {}: {}", dex_path, e);
                }
            }
            dex_paths.push(dex_path);
        } else if name.starts_with(&lib_prefix) && name.ends_with(".so") {
            let filename = name.strip_prefix(&lib_prefix).unwrap_or(name);
            let lib_path = format!("{}/{}", libs_dir, filename);
            if !cache_ok && !data.is_empty() {
                if let Err(e) = atomic_write(&lib_path, data, false) {
                    error!("land_payload_files: failed to write lib {}: {}", lib_path, e);
                }
            }
        }
    }

    Ok((dex_paths, libs_dir, dex_opt_dir))
}

fn register_payload_on_loader(
    env: &mut JNIEnv,
    target_loader: &JObject,
    dex_paths: &[String],
    libs_dir: &str,
    dex_opt_dir: &str,
) -> Result<(), jni::errors::Error> {
    let joined_paths = dex_paths.join(":");

    if joined_paths.is_empty() {
        warn!("No dex paths to register in register_payload_on_loader");
        return Ok(());
    }

    // Register dex paths on the target loader.
    //    Primary: addDexPath (hidden but greylisted, API 26+).
    //    Fallback (API 24/25 or blocked hidden APIs): open the dexes with a
    //    helper DexClassLoader and merge its dexElements into the target
    //    loader, the classic hotfix-style injection.
    if !try_add_dex_path(env, target_loader, &joined_paths) {
        info!(
            "register_payload_on_loader: addDexPath unavailable, using DexClassLoader element injection"
        );
        inject_dex_via_helper_loader(
            env,
            target_loader,
            &joined_paths,
            libs_dir,
            dex_opt_dir,
        )?;
    }

    // Register the decrypted native lib directory so System.loadLibrary
    //    in the original app resolves the extracted .so files.
    //    Primary: addNativePath (hidden, recent platforms only).
    //    Fallback: merge the libs_dir Element harvested from a helper loader
    //    into nativeLibraryPathElements (works down to API 24 and on any
    //    loader type, including BootClassLoader).
    if !try_add_native_path(env, target_loader, libs_dir) {
        info!(
            "register_payload_on_loader: addNativePath unavailable, using native path element injection"
        );
        if let Err(e) = inject_native_lib_dir(env, target_loader, libs_dir) {
            warn!(
                "register_payload_on_loader: inject_native_lib_dir failed: {:?}, clearing JNI exception",
                e
            );
            // CRITICAL: clear any pending JNI exception (e.g. NoSuchFieldError on
            // OEM-modified ART) so it doesn't propagate to Java when we return.
            if env.exception_check().unwrap_or(false) {
                let _ = env.exception_clear();
            }
            // Third fallback: directly System.load() each .so file.
            info!(
                "register_payload_on_loader: falling back to direct System.load for each .so"
            );
            if let Err(e2) = preload_native_libs_direct(env, libs_dir) {
                warn!(
                    "register_payload_on_loader: direct preload also failed: {:?}",
                    e2
                );
            }
        }
    }

    // Runs regardless of which registration path above succeeded: the linker
    // namespace was already created - and its ld_library_path frozen - when
    // ShellApplication's static block loaded libshell.so, so DT_NEEDED entries
    // pointing at sibling payload libraries cannot be resolved by path injection
    // alone. Those siblings have to be dlopen'ed explicitly, dependencies first.
    if let Err(e) = preload_shared_native_deps(env, libs_dir) {
        warn!(
            "register_payload_on_loader: preload_shared_native_deps failed: {:?}",
            e
        );
        if env.exception_check().unwrap_or(false) {
            let _ = env.exception_clear();
        }
    }

    Ok(())
}

fn inject_dex_elements(env: &mut JNIEnv, source_loader: &JObject, target_loader: &JObject) -> Result<(), jni::errors::Error> {
    info!("shell: inject_dex_elements starting...");
    
    let source_path_list = env.get_field(source_loader, "pathList", "Ldalvik/system/DexPathList;")?.l()?;
    let target_path_list = env.get_field(target_loader, "pathList", "Ldalvik/system/DexPathList;")?.l()?;

    let source_elements_obj = env.get_field(source_path_list, "dexElements", "[Ldalvik/system/DexPathList$Element;")?.l()?;
    let source_array: JObjectArray = source_elements_obj.into();

    let target_elements_obj = env.get_field(&target_path_list, "dexElements", "[Ldalvik/system/DexPathList$Element;")?.l()?;
    let target_array: JObjectArray = target_elements_obj.into();
    
    let source_len = env.get_array_length(&source_array)?;
    let target_len = env.get_array_length(&target_array)?;
    debug!("shell: Merging {} new elements into {} existing elements", source_len, target_len);

    let element_cls = env.find_class("dalvik/system/DexPathList$Element")?;
    
    let total_len = source_len + target_len;
    let new_array = env.new_object_array(total_len, element_cls, JObject::null())?;
    
    for i in 0..target_len {
        let elem = env.get_object_array_element(&target_array, i)?;
        env.set_object_array_element(&new_array, i, elem)?;
    }
    
    for i in 0..source_len {
        let elem = env.get_object_array_element(&source_array, i)?;
        env.set_object_array_element(&new_array, target_len + i, elem)?;
    }
    
    let new_array_obj = JObject::from(new_array);
    env.set_field(
        target_path_list,
        "dexElements",
        "[Ldalvik/system/DexPathList$Element;",
        JValue::Object(&new_array_obj)
    )?;

    info!("shell: inject_dex_elements completed successfully");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        clear_dex_load_marker_for_tests, try_mark_dex_load_started, validate_signature_hash,
    };

    #[test]
    fn dex_load_marker_allows_only_first_call() {
        clear_dex_load_marker_for_tests();

        assert!(try_mark_dex_load_started());
        assert!(!try_mark_dex_load_started());

        clear_dex_load_marker_for_tests();
        assert!(try_mark_dex_load_started());
    }

    #[test]
    fn signature_hash_validation_skips_when_expected_is_zero() {
        let expected = [0u8; 32];
        let actual = [1u8; 32];
        assert!(validate_signature_hash(&expected, &actual).is_ok());
    }

    #[test]
    fn signature_hash_validation_fails_on_mismatch() {
        let expected = [7u8; 32];
        let actual = [8u8; 32];
        assert!(validate_signature_hash(&expected, &actual).is_err());
    }

    #[test]
    fn signature_hash_validation_passes_on_exact_match() {
        let expected = [3u8; 32];
        let actual = [3u8; 32];
        assert!(validate_signature_hash(&expected, &actual).is_ok());
    }
}
