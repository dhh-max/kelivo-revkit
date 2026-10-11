package zhou.kelivo.bootstrapdemo;

import android.app.Activity;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.provider.OpenableColumns;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;

public final class MainActivity extends Activity {
    private static final int PICK_APK = 1001;
    private TextView status;

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        BootstrapState.record("activity");
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(48, 64, 48, 64);
        status = new TextView(this);
        status.setTextSize(16);
        status.setText(
                "Kelivo 自研启动 Demo\n\n"
                        + "启动顺序: " + String.join(" → ", BootstrapState.snapshot()) + "\n\n"
                        + "内嵌载荷 SHA-256: " + BootstrapPayload.sha256() + "\n\n"
                        + "Native: " + NativeProbe.status() + "\n\n"
                        + "签名桥接: " + DemoSignatureBridge.status() + "\n\n"
                        + "原始查询: " + DemoSignatureBridge.rawStatus() + "\n\n"
                        + "桥接校验: " + DemoSignatureBridge.bridgeStatus() + "\n\n"
                        + "Android 9 及以上会先经过 component factory。"
        );
        Button pick = new Button(this);
        pick.setText("选择授权测试 APK");
        pick.setOnClickListener(view -> pickApk());
        layout.addView(status, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1));
        layout.addView(pick, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        setContentView(layout);
    }

    private void pickApk() {
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("application/vnd.android.package-archive");
        startActivityForResult(intent, PICK_APK);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != PICK_APK || resultCode != RESULT_OK || data == null) {
            return;
        }
        Uri uri = data.getData();
        if (uri == null) {
            return;
        }
        try {
            File copied = copyToCache(uri);
            status.append("\n\n" + ApkPreflight.inspect(this, copied));
        } catch (Exception error) {
            status.append("\n\n预检失败: " + error.getMessage());
        }
    }

    private File copyToCache(Uri uri) throws Exception {
        String name = "selected.apk";
        try (Cursor cursor = getContentResolver().query(uri, null, null, null, null)) {
            if (cursor != null && cursor.moveToFirst()) {
                int column = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME);
                if (column >= 0) {
                    name = cursor.getString(column);
                }
            }
        }
        File output = new File(getCacheDir(), name.replaceAll("[^A-Za-z0-9._-]", "_"));
        try (InputStream input = getContentResolver().openInputStream(uri);
             FileOutputStream stream = new FileOutputStream(output)) {
            if (input == null) {
                throw new IllegalArgumentException("无法读取选择的文件");
            }
            byte[] buffer = new byte[128 * 1024];
            int count;
            while ((count = input.read(buffer)) != -1) {
                stream.write(buffer, 0, count);
            }
        }
        return output;
    }
}
