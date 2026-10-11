package zhou.solab.signature;

import android.content.pm.PackageInfo;
import android.content.pm.Signature;
import android.os.Build;
import android.os.Parcel;
import android.os.Parcelable;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

public final class PackageInfoCreator implements Parcelable.Creator<PackageInfo> {
    private final Parcelable.Creator<PackageInfo> delegate;
    private final String packageName;
    private final Signature originalSignature;
    public PackageInfoCreator(
            Parcelable.Creator<PackageInfo> delegate,
            String packageName,
            Signature originalSignature) {
        this.delegate = delegate;
        this.packageName = packageName;
        this.originalSignature = originalSignature;
    }

    @Override
    public PackageInfo createFromParcel(Parcel source) {
        PackageInfo info = delegate.createFromParcel(source);
        if (!packageName.equals(info.packageName)) {
            return info;
        }
        if (info.signatures != null && info.signatures.length > 0) {
            info.signatures[0] = originalSignature;
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            replaceSigningInfo(info);
        }
        // 对齐 ApkSignatureKillerEx：不改 applicationInfo.sourceDir/publicSourceDir。
        // App 用真实路径打开 base.apk 时由 native open hook 重定向到原包，
        // 替换 sourceDir 只会劫持加固/热修复/三方 SDK 的路径逻辑，无收益有风险。
        return info;
    }

    private void replaceFirst(Signature[] signatures) {
        if (signatures != null && signatures.length > 0) {
            signatures[0] = originalSignature;
        }
    }

    // signingInfo/getApkContentsSigners/getSigningCertificateHistory 均为 API 28+ 成员。
    // 直接访问会被 R8 重写为宿主 synthetic 类（如 A0/e）的静态方法，
    // 该类不在注入 dex 内，导致目标 App NoClassDefFoundError 闪退。
    // 反射调用 R8 无法重写，保证注入 dex 自包含；对齐 ApkSignatureKillerEx 的全反射实现。
    private static Field signingInfoField;
    private static Method contentsSignersMethod;
    private static Method certHistoryMethod;

    private void replaceSigningInfo(PackageInfo info) {
        try {
            if (signingInfoField == null) {
                signingInfoField = PackageInfo.class.getField("signingInfo");
                contentsSignersMethod = signingInfoField.getType().getMethod("getApkContentsSigners");
                certHistoryMethod = signingInfoField.getType().getMethod("getSigningCertificateHistory");
            }
            Object signingInfo = signingInfoField.get(info);
            if (signingInfo == null) {
                return;
            }
            replaceFirst((Signature[]) contentsSignersMethod.invoke(signingInfo));
            replaceFirst((Signature[]) certHistoryMethod.invoke(signingInfo));
        } catch (Throwable ignored) {
            // 反射不可用时保持系统返回值，签名替换只做能做的部分
        }
    }

    @Override
    public PackageInfo[] newArray(int size) {
        return delegate.newArray(size);
    }
}
