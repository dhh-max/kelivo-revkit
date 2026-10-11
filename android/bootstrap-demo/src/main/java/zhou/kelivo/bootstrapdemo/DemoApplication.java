package zhou.kelivo.bootstrapdemo;

import android.app.Application;
import android.content.Context;

public final class DemoApplication extends Application {
    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);
        BootstrapState.record("application attach");
        BootstrapPayload.prepare(this);
        DemoSignatureBridge.install(this);
    }

    @Override
    public void onCreate() {
        BootstrapState.record("application");
        super.onCreate();
    }
}
