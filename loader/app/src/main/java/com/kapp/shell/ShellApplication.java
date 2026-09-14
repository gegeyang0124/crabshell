package com.kapp.shell;

import android.app.Application;
import android.content.Context;
import android.util.Log;

import java.io.File;
import java.util.zip.ZipFile;

import java.lang.reflect.Method;

public class ShellApplication extends Application {
    private static final String TAG = "ShellApplication";
    private Application originalApp;

    /**
     * Bypass Android hidden API restrictions (Android 9-14).
     * Uses the "double reflection" trick: calling getDeclaredMethod via
     * Method.invoke changes the caller identity in ART's hidden-API check,
     * so the exemption call succeeds even on Android 12+ (API 31+).
     *
     * MUST be called before any hidden-API access (e.g. addDexPath, pathList).
     */
    private static void bypassHiddenApiRestrictions() {
        try {
            // 1. Get Method.getDeclaredMethod itself
            Method getDeclaredMethod = Method.class.getDeclaredMethod(
                    "getDeclaredMethod", String.class, Class[].class);

            // 2. Get VMRuntime class
            Class<?> vmRuntimeClass = Class.forName("dalvik.system.VMRuntime");

            // 3. Call VMRuntime.class.getDeclaredMethod("setHiddenApiExemptions", String[].class)
            //    via the Method object (bypasses hidden-API caller check)
            Method setHiddenApiExemptions = (Method) getDeclaredMethod.invoke(
                    vmRuntimeClass,
                    "setHiddenApiExemptions",
                    new Class[]{String[].class});

            // 4. Get VMRuntime.getRuntime() via the same trick
            Method getRuntime = (Method) getDeclaredMethod.invoke(
                    vmRuntimeClass, "getRuntime", new Class[]{});
            Object vmRuntime = getRuntime.invoke(null);

            // 5. Exempt ALL APIs ("L" prefix matches all JNI descriptors)
            setHiddenApiExemptions.invoke(vmRuntime, (Object) new String[]{"L"});
            Log.d(TAG, "Hidden API exemptions set successfully");
        } catch (Exception e) {
            Log.w(TAG, "Failed to bypass hidden API restrictions: " + e.getMessage());
        }
    }

    static {
        bypassHiddenApiRestrictions();
        // libshell.so is deliberately NOT loaded here - see ensureNativeLoaded.
    }

    private static boolean sNativeLoaded = false;

    /**
     * Loads libshell.so once. Callers must seed the payload native directory
     * first.
     *
     * <p>This process's first native load is what makes libnativeloader create
     * the linker namespace for the application's PathClassLoader, and the
     * namespace snapshots {@code getLdLibraryPath()} at that instant and never
     * refreshes it. Loading from the static initializer therefore freezes the
     * search path to the APK's own lib directory, which after packing contains
     * nothing but libshell.so; every payload .so decrypted into the cache
     * directory is then rejected as inaccessible on Android 7, and payload
     * libraries also cannot resolve their {@code DT_NEEDED} siblings.
     */
    static synchronized void ensureNativeLoaded() {
        if (sNativeLoaded)
            return;
        sNativeLoaded = true;
        try {
            System.loadLibrary("shell");
        } catch (UnsatisfiedLinkError e) {
            Log.e(TAG, "Failed to load native library", e);
        }
    }

    private static boolean sDexLoaded = false;

    // Native method to load DEX from memory or file
    private native void nativeLoadDex(Context context, int version);

    // Native method to load DEX using ApplicationInfo (earlier than
    // attachBaseContext)
    public static native void nativeLoadDexWithAppInfo(android.content.pm.ApplicationInfo appInfo, ClassLoader cl,
            int version);

    public static synchronized void ensureDexLoaded(Context context) {
        if (sDexLoaded)
            return;
        // Must happen before ensureNativeLoaded(): the payload directory has to
        // be inside getLdLibraryPath() when the linker namespace is created.
        // Mirrors libs_dir in lib.rs, "<getCacheDir()>/native_libs".
        NativeLibLoader.seedNativeLibraryDir(context.getClassLoader(),
                context.getCacheDir().getAbsolutePath() + "/native_libs");
        ensureNativeLoaded();
        new ShellApplication().nativeLoadDex(context, android.os.Build.VERSION.SDK_INT);
        sDexLoaded = true;
    }

    public static synchronized void ensureDexLoaded(android.content.pm.ApplicationInfo appInfo, ClassLoader cl) {
        if (sDexLoaded)
            return;
        // No Context on this path, so build the directory the way lib.rs does:
        // "<dataDir>/cache/native_libs".
        if (appInfo.dataDir != null) {
            NativeLibLoader.seedNativeLibraryDir(cl, appInfo.dataDir + "/cache/native_libs");
        }
        ensureNativeLoaded();
        nativeLoadDexWithAppInfo(appInfo, cl, android.os.Build.VERSION.SDK_INT);
        sDexLoaded = true;
    }

    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);
        Log.d(TAG, "attachBaseContext: Starting shell logic");
        ensureDexLoaded(base);
    }

    @Override
    public void onCreate() {
        super.onCreate();
        Log.d(TAG, "onCreate: ShellApplication started");
        ensureDexLoaded(getApplicationContext());

        try {
            String originalAppName = null;
            android.content.pm.ApplicationInfo appInfo = getPackageManager().getApplicationInfo(getPackageName(),
                    android.content.pm.PackageManager.GET_META_DATA);
            if (appInfo.metaData != null) {
                originalAppName = appInfo.metaData.getString("kapp.original_application");
            }

            if (originalAppName == null || originalAppName.isEmpty()) {
                originalAppName = ShellComponentFactory.ORIGINAL_APP;
            }

            if (originalAppName == null || originalAppName.isEmpty()) {
                Log.e(TAG, "onCreate: No original application class found");
                return;
            }

            Log.d(TAG, "onCreate: Loading original application: " + originalAppName);
            Class<?> clazz = getClassLoader().loadClass(originalAppName);
            originalApp = (Application) clazz.newInstance();

            // Attach context
            java.lang.reflect.Method attachMethod = Application.class.getDeclaredMethod("attach", Context.class);
            attachMethod.setAccessible(true);
            attachMethod.invoke(originalApp, getBaseContext());

            // Replace ShellApplication with originalApp in the system
            replaceApplication(getBaseContext(), originalApp);

            // Inject extracted assets
            injectAssets(getApplicationContext());

            // Initialize WorkManager via reflection if originalApp provides configuration
            initializeWorkManager(originalApp);

            Log.d(TAG, "onCreate: Calling original application onCreate");
            originalApp.onCreate();

        } catch (Exception e) {
            Log.e(TAG, "onCreate: Failed to delegate to original application", e);
            throw new RuntimeException(e);
        }
    }

    private void injectAssets(Context context) {
        try {
            File assetsZip = new File(context.getFilesDir(), "kapp_assets.zip");
            if (!assetsZip.exists()) {
                Log.w(TAG, "injectAssets: kapp_assets.zip does not exist, skipping");
                return;
            }
            if (assetsZip.length() == 0L) {
                Log.w(TAG, "injectAssets: kapp_assets.zip is empty, skipping");
                return;
            }
            try (ZipFile zipFile = new ZipFile(assetsZip)) {
                if (zipFile.size() == 0) {
                    Log.w(TAG, "injectAssets: kapp_assets.zip has no entries, skipping");
                    return;
                }
            }

            android.content.res.AssetManager am = context.getAssets();
            java.lang.reflect.Method addAssetPath = android.content.res.AssetManager.class
                    .getDeclaredMethod("addAssetPath", String.class);
            addAssetPath.setAccessible(true);

            String path = assetsZip.getAbsolutePath();
            Log.d(TAG, "injectAssets: Adding asset path: " + path);

            Object cookie = addAssetPath.invoke(am, path);
            Log.d(TAG, "injectAssets: Result cookie: " + cookie);
            if (cookie instanceof Integer && ((Integer) cookie) == 0) {
                Log.w(TAG, "injectAssets: addAssetPath returned 0, treating as no-op");
            }

        } catch (Exception e) {
            Log.e(TAG, "injectAssets: Failed to inject assets", e);
        }
    }

    private void initializeWorkManager(Application app) {
        try {
            Log.d(TAG, "Checking for WorkManager configuration...");
            // Reflectively check for androidx.work.Configuration$Provider
            Class<?> providerClass = tryLoadClass("androidx.work.Configuration$Provider");
            if (providerClass == null) {
                Log.d(TAG, "androidx.work.Configuration$Provider not found, skipping WorkManager init");
                return;
            }

            if (providerClass.isInstance(app)) {
                Log.d(TAG, "Original app implements Configuration.Provider, retrieving config...");
                java.lang.reflect.Method getConfigMethod = providerClass.getMethod("getWorkManagerConfiguration");
                Object config = getConfigMethod.invoke(app);

                if (config != null) {
                    Log.d(TAG, "Initializing WorkManager with reflected config...");
                    Class<?> workManagerClass = tryLoadClass("androidx.work.WorkManager");
                    if (workManagerClass != null) {
                        java.lang.reflect.Method initMethod = workManagerClass.getMethod("initialize", Context.class,
                                tryLoadClass("androidx.work.Configuration"));
                        initMethod.invoke(null, this, config);
                        Log.d(TAG, "WorkManager initialized successfully");
                    }
                }
            } else {
                Log.d(TAG, "Original app does NOT implement Configuration.Provider");
            }
        } catch (Exception e) {
            // Log but don't crash if WorkManager init fails - app might might still work
            Log.w(TAG, "Failed to initialize WorkManager via reflection", e);
        }
    }

    private void replaceApplication(Context baseContext, Application newApp) {
        try {
            Log.d(TAG, "replaceApplication: Swapping Application instance...");

            // 1. Get ActivityThread
            Class<?> activityThreadClass = Class.forName("android.app.ActivityThread");
            java.lang.reflect.Method currentActivityThreadMethod = activityThreadClass
                    .getDeclaredMethod("currentActivityThread");
            Object activityThread = currentActivityThreadMethod.invoke(null);

            // 2. Get LoadedApk (mBoundApplication is not accessible easily, get it via
            // ContextImpl using reflection/methods)
            // Or easier: ContextImpl.mPackageInfo is LoadedApk
            Object loadedApk = null;
            try {
                java.lang.reflect.Field packageInfoField = baseContext.getClass().getDeclaredField("mPackageInfo");
                packageInfoField.setAccessible(true);
                loadedApk = packageInfoField.get(baseContext);
            } catch (Exception e) {
                // Fallback attempt
                Log.w(TAG, "Failed to get LoadedApk from Context, trying ActivityThread.mBoundApplication...");
            }

            if (loadedApk == null) {
                // Try from ActivityThread
                java.lang.reflect.Field mBoundApplicationField = activityThreadClass
                        .getDeclaredField("mBoundApplication");
                mBoundApplicationField.setAccessible(true);
                Object appBindData = mBoundApplicationField.get(activityThread);
                java.lang.reflect.Field infoField = appBindData.getClass().getDeclaredField("info");
                infoField.setAccessible(true);
                loadedApk = infoField.get(appBindData);
            }

            if (loadedApk != null) {
                // 3. Replace mApplication in LoadedApk
                Class<?> loadedApkClass = Class.forName("android.app.LoadedApk");
                java.lang.reflect.Field mApplicationField = loadedApkClass.getDeclaredField("mApplication");
                mApplicationField.setAccessible(true);
                mApplicationField.set(loadedApk, newApp);

                // 4. Update mAllApplications list in ActivityThread
                java.lang.reflect.Field mAllApplicationsField = activityThreadClass
                        .getDeclaredField("mAllApplications");
                mAllApplicationsField.setAccessible(true);
                java.util.ArrayList<Application> allApplications = (java.util.ArrayList<Application>) mAllApplicationsField
                        .get(activityThread);
                allApplications.remove(this);
                allApplications.add(newApp);

                // 5. Update mInitialApplication in ActivityThread
                java.lang.reflect.Field mInitialApplicationField = activityThreadClass
                        .getDeclaredField("mInitialApplication");
                mInitialApplicationField.setAccessible(true);
                mInitialApplicationField.set(activityThread, newApp);

                Log.d(TAG, "replaceApplication: Success!");
            } else {
                Log.e(TAG, "replaceApplication: Failed to find LoadedApk");
            }

        } catch (Exception e) {
            Log.e(TAG, "replaceApplication: Failed", e);
            // Non-fatal? Maybe, but likely will crash later on cast.
        }
    }

    private Class<?> tryLoadClass(String name) {
        try {
            return getClassLoader().loadClass(name);
        } catch (ClassNotFoundException e) {
            return null;
        }
    }
}
