package zhou.kelivo.bootstrapdemo;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Build;
import android.os.Parcel;
import android.os.Parcelable;
import android.util.Base64;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.lang.reflect.Method;
import java.util.IdentityHashMap;
import java.util.Map;

public final class DemoSignatureBridge {
    private static volatile String status = "not installed";
    private static volatile String rawStatus = "not checked";
    private static volatile String bridgeStatus = "not checked";
    private static volatile boolean configured;
    private static volatile String configuredPackage;
    private static volatile Signature configuredSignature;

    private DemoSignatureBridge() {
    }

    public static synchronized void install(Context context) {
        if (configured) {
            verifyConfigured(context);
            return;
        }
        try {
            PackageInfo raw = packageInfo(context);
            Signature actual = packageSignature(raw);
            Signature expected = differentSignature(actual);
            rawStatus = actual.toCharsString().equals(expected.toCharsString())
                    ? "unexpectedly matched"
                    : "expected mismatch";
            enableHiddenApiAccess();
            boolean installed = installCreator(context.getPackageName(), expected);
            PackageInfo bridged = parcelCopy(raw);
            boolean passed = installed && matchesBridge(bridged, expected);
            bridgeStatus = passed ? "passed via PackageInfo parcel bridge" : "failed";
            status = passed ? "installed" : "unavailable on this Android build";
        } catch (Throwable error) {
            status = "failed: " + error.getClass().getSimpleName();
            rawStatus = "unavailable";
            bridgeStatus = "unavailable";
        }
        BootstrapState.record("signature bridge: " + status);
    }

    public static synchronized boolean installFromClassLoader(ClassLoader classLoader) {
        try (InputStream input = classLoader.getResourceAsStream(
                BootstrapConfig.ENTRY)) {
            if (input == null) {
                return false;
            }
            JSONObject config = new JSONObject(readUtf8(input));
            String packageName = config.getString("targetPackage");
            byte[] certificate = Base64.decode(config.getString("signatureBase64"), Base64.DEFAULT);
            if (packageName.isEmpty() || certificate.length == 0) {
                throw new IllegalArgumentException("empty bootstrap configuration");
            }
            enableHiddenApiAccess();
            boolean installed = installCreator(packageName, new Signature(certificate));
            configured = installed;
            configuredPackage = packageName;
            configuredSignature = new Signature(certificate);
            status = installed ? "installed from bootstrap configuration" : "unavailable on this Android build";
            rawStatus = installed ? "configured for target package" : "unavailable";
            bridgeStatus = installed ? "waiting for target PackageInfo parcel" : "unavailable";
            BootstrapState.record("signature bridge: " + status);
            return installed;
        } catch (Throwable error) {
            status = "bootstrap configuration failed: " + error.getClass().getSimpleName();
            rawStatus = "unavailable";
            bridgeStatus = "unavailable";
            BootstrapState.record("signature bridge: " + status);
            return false;
        }
    }

    public static String status() {
        return status;
    }

    public static String rawStatus() {
        return rawStatus;
    }

    public static String bridgeStatus() {
        return bridgeStatus;
    }

    private static PackageInfo packageInfo(Context context) throws Exception {
        int flags = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P
                ? PackageManager.GET_SIGNING_CERTIFICATES
                : PackageManager.GET_SIGNATURES;
        return context.getPackageManager().getPackageInfo(context.getPackageName(), flags);
    }

    private static void verifyConfigured(Context context) {
        try {
            PackageInfo raw = packageInfo(context);
            Signature actual = packageSignature(raw);
            Signature expected = configuredSignature;
            rawStatus = actual.toCharsString().equals(expected.toCharsString())
                    ? "unexpectedly matched"
                    : "expected mismatch";
            PackageInfo bridged = parcelCopy(raw);
            boolean passed = context.getPackageName().equals(configuredPackage)
                    && matchesBridge(bridged, expected);
            bridgeStatus = passed ? "passed via bootstrap configuration" : "failed";
            status = passed ? "installed from bootstrap configuration" : "unavailable on this Android build";
        } catch (Throwable error) {
            status = "bootstrap verification failed: " + error.getClass().getSimpleName();
            bridgeStatus = "unavailable";
        }
        BootstrapState.record("signature bridge: " + status);
    }

    private static String readUtf8(InputStream input) throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] buffer = new byte[4096];
        int count;
        while ((count = input.read(buffer)) != -1) {
            output.write(buffer, 0, count);
        }
        return output.toString("UTF-8");
    }

    private static Signature packageSignature(PackageInfo info) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P
                && info.signingInfo != null
                && info.signingInfo.getApkContentsSigners().length == 1) {
            return info.signingInfo.getApkContentsSigners()[0];
        }
        if (info.signatures != null && info.signatures.length == 1) {
            return info.signatures[0];
        }
        throw new IllegalStateException("missing package signature");
    }

    private static Signature differentSignature(Signature actual) {
        byte[] bytes = actual.toByteArray().clone();
        if (bytes.length == 0) {
            throw new IllegalStateException("empty signature");
        }
        bytes[bytes.length - 1] ^= 0x01;
        return new Signature(bytes);
    }

    private static boolean matchesBridge(PackageInfo info, Signature expected) {
        boolean legacyMatches = info.signatures != null
                && info.signatures.length == 1
                && info.signatures[0].toCharsString().equals(expected.toCharsString());
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P || info.signingInfo == null) {
            return legacyMatches;
        }
        Signature[] current = info.signingInfo.getApkContentsSigners();
        return legacyMatches
                && current.length == 1
                && current[0].toCharsString().equals(expected.toCharsString());
    }

    private static PackageInfo parcelCopy(PackageInfo source) {
        Parcel parcel = Parcel.obtain();
        try {
            source.writeToParcel(parcel, 0);
            parcel.setDataPosition(0);
            return PackageInfo.CREATOR.createFromParcel(parcel);
        } finally {
            parcel.recycle();
        }
    }

    private static boolean installCreator(String packageName, Signature expected) {
        try {
            Parcelable.Creator<PackageInfo> current = PackageInfo.CREATOR;
            if (!(current instanceof SignatureCreator)) {
                Field field = PackageInfo.class.getDeclaredField("CREATOR");
                field.setAccessible(true);
                field.set(null, new SignatureCreator(current, packageName, expected));
            }
            clearStaticMap("mCreators");
            clearStaticMap("sPairedCreators");
            return PackageInfo.CREATOR instanceof SignatureCreator;
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static void enableHiddenApiAccess() {
        try {
            Method forName = Class.class.getDeclaredMethod("forName", String.class);
            Method getMethod = Class.class.getDeclaredMethod(
                    "getDeclaredMethod", String.class, Class[].class);
            Class<?> runtimeClass = (Class<?>) forName.invoke(null, "dalvik.system.VMRuntime");
            Method getRuntime = (Method) getMethod.invoke(runtimeClass, "getRuntime", null);
            Object runtime = getRuntime.invoke(null);
            Method exemptions = (Method) getMethod.invoke(
                    runtimeClass, "setHiddenApiExemptions", new Class[]{String[].class});
            exemptions.invoke(runtime, (Object) new String[]{"Landroid/"});
        } catch (Throwable ignored) {
        }
    }

    private static void clearStaticMap(String fieldName) {
        try {
            Field field = Parcel.class.getDeclaredField(fieldName);
            field.setAccessible(true);
            Object value = field.get(null);
            if (value instanceof Map) {
                ((Map<?, ?>) value).clear();
            }
        } catch (Throwable ignored) {
        }
    }

    private static final class SignatureCreator implements Parcelable.Creator<PackageInfo> {
        private final Parcelable.Creator<PackageInfo> delegate;
        private final String packageName;
        private final Signature expected;

        SignatureCreator(
                Parcelable.Creator<PackageInfo> delegate,
                String packageName,
                Signature expected
        ) {
            this.delegate = delegate;
            this.packageName = packageName;
            this.expected = expected;
        }

        @Override
        public PackageInfo createFromParcel(Parcel source) {
            PackageInfo info = delegate.createFromParcel(source);
            if (packageName.equals(info.packageName)) {
                info.signatures = new Signature[]{expected};
                replaceSigningInfo(info);
            }
            return info;
        }

        @Override
        public PackageInfo[] newArray(int size) {
            return delegate.newArray(size);
        }

        private void replaceSigningInfo(PackageInfo info) {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P || info.signingInfo == null) {
                return;
            }
            try {
                replaceSignatureArrays(info.signingInfo, new IdentityHashMap<Object, Boolean>(), 0);
            } catch (Throwable ignored) {
            }
        }

        private void replaceSignatureArrays(
                Object target,
                IdentityHashMap<Object, Boolean> visited,
                int depth
        ) throws IllegalAccessException {
            if (target == null || depth > 2 || visited.put(target, Boolean.TRUE) != null) {
                return;
            }
            for (Class<?> type = target.getClass(); type != null && type != Object.class;
                 type = type.getSuperclass()) {
                for (Field field : type.getDeclaredFields()) {
                    if (Modifier.isStatic(field.getModifiers())) {
                        continue;
                    }
                    field.setAccessible(true);
                    if (field.getType() == Signature[].class) {
                        field.set(target, new Signature[]{expected});
                    } else if (!field.getType().isPrimitive()
                            && field.getType().getName().startsWith("android.content.pm.")) {
                        replaceSignatureArrays(field.get(target), visited, depth + 1);
                    }
                }
            }
        }
    }
}
