package zhou.kelivo.bootstrapdemo;

import android.app.AppComponentFactory;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;

final class BootstrapConfig {
    static final String ENTRY = "assets/kelivo-bootstrap/bridge.json";
    private static volatile boolean factoryResolved;
    private static volatile AppComponentFactory factory;

    private BootstrapConfig() {
    }

    static AppComponentFactory originalFactory(ClassLoader classLoader) {
        if (factoryResolved) {
            return factory;
        }
        synchronized (BootstrapConfig.class) {
            if (!factoryResolved) {
                factory = loadOriginalFactory(classLoader);
                factoryResolved = true;
            }
            return factory;
        }
    }

    private static AppComponentFactory loadOriginalFactory(ClassLoader classLoader) {
        try (InputStream input = classLoader.getResourceAsStream(ENTRY)) {
            if (input == null) {
                return null;
            }
            String name = new JSONObject(readUtf8(input)).optString("originalComponentFactory");
            if (name.isEmpty() || AppComponentFactory.class.getName().equals(name)
                    || BootstrapFactory.class.getName().equals(name)) {
                return null;
            }
            Class<?> type = classLoader.loadClass(name);
            if (!AppComponentFactory.class.isAssignableFrom(type)) {
                return null;
            }
            return (AppComponentFactory) type.getDeclaredConstructor().newInstance();
        } catch (Throwable ignored) {
            return null;
        }
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
}
