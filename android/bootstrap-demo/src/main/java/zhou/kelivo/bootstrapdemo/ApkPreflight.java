package zhou.kelivo.bootstrapdemo;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Build;

import java.io.File;
import java.security.MessageDigest;
import java.util.zip.ZipFile;

final class ApkPreflight {
    private ApkPreflight() {
    }

    static String inspect(Context context, File apk) throws Exception {
        try (ZipFile zip = new ZipFile(apk)) {
            if (zip.getEntry("AndroidManifest.xml") == null) {
                throw new IllegalArgumentException("不是有效 APK: 缺少 AndroidManifest.xml");
            }
            boolean hasDex = zip.stream()
                    .anyMatch(entry -> entry.getName().matches("classes(\\d*)?\\.dex"));
            if (!hasDex) {
                throw new IllegalArgumentException("不是有效 APK: 缺少 classes.dex");
            }
        }
        int flags = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P
                ? PackageManager.GET_SIGNING_CERTIFICATES
                : PackageManager.GET_SIGNATURES;
        PackageInfo info = context.getPackageManager().getPackageArchiveInfo(apk.getAbsolutePath(), flags);
        if (info == null) {
            throw new IllegalArgumentException("无法读取 APK 包信息");
        }
        Signature signature = signature(info);
        return "已读取 APK\n\n"
                + "包名: " + info.packageName + "\n"
                + "版本: " + info.versionName + " (" + info.getLongVersionCode() + ")\n"
                + "大小: " + apk.length() + " bytes\n"
                + "原始签名 SHA-256: " + sha256(signature.toByteArray()) + "\n\n"
                + "当前仅完成预检，不会修改原包。";
    }

    private static Signature signature(PackageInfo info) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P
                && info.signingInfo != null
                && info.signingInfo.getApkContentsSigners().length == 1) {
            return info.signingInfo.getApkContentsSigners()[0];
        }
        if (info.signatures != null && info.signatures.length == 1) {
            return info.signatures[0];
        }
        throw new IllegalArgumentException("APK 没有可读取的单一签名");
    }

    private static String sha256(byte[] bytes) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(bytes);
        StringBuilder value = new StringBuilder();
        for (byte item : digest.digest()) {
            value.append(String.format("%02x", item & 0xff));
        }
        return value.toString();
    }
}
