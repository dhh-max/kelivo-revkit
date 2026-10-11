package zhou.solab.frida;

import android.app.Application;
import android.content.Context;

/**
 * 注入到目标 APK 的代理 Application（Frida gadget 宿主侧）。
 *
 * 由 {@code ApkSignatureBypassInjector} 的 gadget 模式从宿主 dex 抽出并注入：
 * 目标 manifest 的 application 指向本类，本类继承目标原有 Application，在
 * attachBaseContext 里先把 gadget 加载起来，再交回原有 Application 的初始化。
 *
 * 注意：本类会被 R8 处理，必须在 proguard-rules.pro 里 keep（按类型从宿主
 * dex 抽取）。
 */
public class FridaGadgetProxyApplication extends Application {

    @Override
    protected void attachBaseContext(Context base) {
        // gadget 的默认交互模式是 listen 127.0.0.1:27042（无配置文件时）。
        // 加载失败不能影响目标 App 启动：这里只做 best-effort 并留下痕迹。
        try {
            System.loadLibrary("frida-gadget");
        } catch (Throwable error) {
            android.util.Log.w("SoLabFrida", "frida-gadget load failed: " + error);
        }
        super.attachBaseContext(base);
    }
}
