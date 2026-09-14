package com.kapp.shell;

import android.util.Log;

import java.io.File;
import java.lang.reflect.Field;
import java.util.List;

/**
 * Loads payload native libraries from Java instead of from JNI.
 *
 * <p>{@code System.load} resolves the owning ClassLoader with
 * {@code Reflection.getCallerClass()} inside {@code Runtime.load0}. When the
 * call originates in native code (libshell.so) that lookup does not reliably
 * yield the application's PathClassLoader, and ART only searches the shared
 * libraries registered against the <em>declaring</em> class's loader when it
 * resolves a JNI method. A library registered under the wrong loader therefore
 * loads fine but its native methods keep reporting "No implementation found".
 *
 * <p>This class lives in the bootstrap dex, i.e. it is loaded by the very same
 * PathClassLoader that the payload dexes are injected into, so every library it
 * loads is registered where the payload classes can see it.
 */
public final class NativeLibLoader {

    private static final String TAG = "KAppShell";

    private NativeLibLoader() {
    }

    /**
     * Loads the given absolute paths in the supplied order.
     *
     * <p>The caller is responsible for putting every dependency before the
     * library that needs it: the linker resolves {@code DT_NEEDED} against the
     * namespace's already-loaded list, whose search path was snapshotted before
     * the payload was decrypted and can no longer be updated.
     *
     * <p>Failures are collected rather than thrown so that one unloadable
     * library does not abort the rest of the batch.
     *
     * @return number of paths that could not be loaded
     */
    public static int loadInOrder(String[] paths) {
        if (paths == null) {
            return 0;
        }
        int failures = 0;
        for (String path : paths) {
            if (path == null || path.isEmpty()) {
                continue;
            }
            try {
                System.load(path);
                Log.d(TAG, "NativeLibLoader: loaded " + path);
            } catch (Throwable t) {
                failures++;
                Log.e(TAG, "NativeLibLoader: failed to load " + path, t);
            }
        }
        return failures;
    }

    /**
     * Registers {@code dir} as a native library directory of {@code loader},
     * to be called <em>before</em> that loader performs its first native load.
     *
     * <p>libnativeloader creates a ClassLoader's linker namespace on the
     * loader's first {@code System.loadLibrary}, snapshotting
     * {@code BaseDexClassLoader.getLdLibraryPath()} - which is exactly this
     * list joined with ':' - into the namespace's {@code ld_library_path}. The
     * namespace is never refreshed afterwards, so a directory missing at that
     * instant stays missing for the whole process lifetime.
     *
     * <p>Android 7.0 marks application namespaces isolated, and bionic's
     * {@code android_namespace_t::is_accessible()} rejects any library that
     * lives in neither {@code ld_library_paths_}, {@code default_library_paths_}
     * nor {@code permitted_paths_}. After packing, the APK's own lib directory
     * holds nothing but libshell.so and the real libraries sit in the cache
     * directory, so every payload {@code System.loadLibrary} dies with
     * "is not accessible for the namespace". SDKs that swallow the failure -
     * Baidu's FaceAuth catches Throwable and only prints the stack - surface it
     * much later as "No implementation found" on their native methods.
     *
     * <p>Seeding fixes {@code DT_NEEDED} resolution as well: bionic resolves a
     * dependency's soname against {@code ld_library_paths_}, which no longer
     * mentions the payload directory.
     *
     * <p>{@code dir} must exist or be creatable. {@code create_namespace()}
     * runs the path through {@code parse_path()} -> {@code resolve_paths()},
     * which silently drops every entry that does not resolve to an existing
     * directory.
     *
     * @return true if {@code dir} is known to the loader afterwards
     */
    @SuppressWarnings("unchecked")
    public static boolean seedNativeLibraryDir(ClassLoader loader, String dir) {
        if (loader == null || dir == null || dir.isEmpty()) {
            return false;
        }

        File directory = new File(dir);
        if (!directory.isDirectory() && !directory.mkdirs()) {
            Log.w(TAG, "NativeLibLoader: cannot create " + dir + ", namespace seeding skipped");
            return false;
        }

        try {
            // pathList is declared on BaseDexClassLoader, the instance may be a
            // PathClassLoader or a DexClassLoader.
            Field pathListField = findField(loader.getClass(), "pathList");
            if (pathListField == null) {
                Log.w(TAG, "NativeLibLoader: no pathList on " + loader.getClass().getName());
                return false;
            }
            pathListField.setAccessible(true);
            Object pathList = pathListField.get(loader);
            if (pathList == null) {
                return false;
            }

            Field dirsField = findField(pathList.getClass(), "nativeLibraryDirectories");
            if (dirsField == null) {
                Log.w(TAG, "NativeLibLoader: no nativeLibraryDirectories on "
                        + pathList.getClass().getName());
                return false;
            }
            dirsField.setAccessible(true);
            Object value = dirsField.get(pathList);
            if (!(value instanceof List)) {
                return false;
            }

            List<File> directories = (List<File>) value;
            if (directories.contains(directory)) {
                return true;
            }
            // Appended rather than prepended, matching DexPathList.addNativePath:
            // ld_library_paths_ is searched ahead of default_library_paths_
            // (/system/lib), so a payload-bundled libc++_shared.so still wins
            // over the platform one without reordering anything else.
            directories.add(directory);
            Log.d(TAG, "NativeLibLoader: seeded " + dir);
            return true;
        } catch (Throwable t) {
            // Best effort only - OEM builds may rename or drop these fields, and
            // the loader has its own fallbacks for that case.
            Log.w(TAG, "NativeLibLoader: failed to seed " + dir, t);
            return false;
        }
    }

    private static Field findField(Class<?> type, String name) {
        for (Class<?> current = type; current != null; current = current.getSuperclass()) {
            try {
                return current.getDeclaredField(name);
            } catch (NoSuchFieldException ignored) {
                // keep walking up the hierarchy
            }
        }
        return null;
    }
}
