package zhou.kelivo.bootstrapdemo;

import android.app.AppComponentFactory;
import android.app.Activity;
import android.app.Application;
import android.app.Service;
import android.content.BroadcastReceiver;
import android.content.ContentProvider;
import android.content.Intent;

import java.io.InputStream;

public final class BootstrapFactory extends AppComponentFactory {
    @Override
    public Application instantiateApplication(
            ClassLoader classLoader,
            String className
    ) throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        BootstrapState.record("component factory");
        BootstrapState.record("factory asset: " + hasPayload(classLoader));
        DemoSignatureBridge.installFromClassLoader(classLoader);
        AppComponentFactory original = BootstrapConfig.originalFactory(classLoader);
        if (original != null) {
            BootstrapState.record("original component factory");
            return original.instantiateApplication(classLoader, className);
        }
        return super.instantiateApplication(classLoader, className);
    }

    @Override
    public Activity instantiateActivity(
            ClassLoader classLoader,
            String className,
            Intent intent
    ) throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        AppComponentFactory original = BootstrapConfig.originalFactory(classLoader);
        return original != null
                ? original.instantiateActivity(classLoader, className, intent)
                : super.instantiateActivity(classLoader, className, intent);
    }

    @Override
    public BroadcastReceiver instantiateReceiver(
            ClassLoader classLoader,
            String className,
            Intent intent
    ) throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        AppComponentFactory original = BootstrapConfig.originalFactory(classLoader);
        return original != null
                ? original.instantiateReceiver(classLoader, className, intent)
                : super.instantiateReceiver(classLoader, className, intent);
    }

    @Override
    public Service instantiateService(
            ClassLoader classLoader,
            String className,
            Intent intent
    ) throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        AppComponentFactory original = BootstrapConfig.originalFactory(classLoader);
        return original != null
                ? original.instantiateService(classLoader, className, intent)
                : super.instantiateService(classLoader, className, intent);
    }

    @Override
    public ContentProvider instantiateProvider(
            ClassLoader classLoader,
            String className
    ) throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        AppComponentFactory original = BootstrapConfig.originalFactory(classLoader);
        return original != null
                ? original.instantiateProvider(classLoader, className)
                : super.instantiateProvider(classLoader, className);
    }

    private static boolean hasPayload(ClassLoader classLoader) {
        try (InputStream input = classLoader.getResourceAsStream("assets/bootstrap/payload.txt")) {
            return input != null && input.read() != -1;
        } catch (Exception ignored) {
            return false;
        }
    }
}
