"""Hook生成器 - 自动生成Frida/Xposed hook脚本"""
import re

class HookGenerator:
    """根据分析结果自动生成Hook脚本"""

    @staticmethod
    def generate_frida_script(target_class, target_method=None, verbose=False,
                               trace_args=False, trace_return=False, bypass_flags=None):
        """生成Frida hook脚本

        Args:
            target_class: 目标类名（Lcom/example/Class; 格式）
            target_method: 目标方法名，None=hook所有方法
            verbose: 是否输出详细日志
            trace_args: 是否追踪参数
            trace_return: 是否追踪返回值
            bypass_flags: dict, 绕过选项 {
                'root': True, 'debug': True, 'ssl': True,
                'signature': True, 'emulator': True
            }
        """
        # 转换类名格式
        if target_class.startswith('L') and target_class.endswith(';'):
            cls_path = target_class[1:-1].replace('/', '.')
        else:
            cls_path = target_class.replace('/', '.').replace('L', '').replace(';', '')

        lines = [
            '// Auto-generated Frida Hook Script',
            '// Target: ' + cls_path,
            'Java.perform(function() {',
        ]

        if bypass_flags:
            if bypass_flags.get('root'):
                lines.extend(HookGenerator._frida_bypass_root())
            if bypass_flags.get('debug'):
                lines.extend(HookGenerator._frida_bypass_debug())
            if bypass_flags.get('ssl'):
                lines.extend(HookGenerator._frida_bypass_ssl())
            if bypass_flags.get('signature'):
                lines.extend(HookGenerator._frida_bypass_signature())
            if bypass_flags.get('emulator'):
                lines.extend(HookGenerator._frida_bypass_emulator())

        if target_method:
            lines.append(f'    var targetClass = Java.use("{cls_path}");')
            lines.append(f'    targetClass.{target_method}.implementation = function() {{')
            if trace_args:
                lines.append('        console.log("[*] ' + target_method + ' called with args:");')
                lines.append('        for (var i = 0; i < arguments.length; i++) {')
                lines.append('            console.log("    arg[" + i + "]: " + arguments[i]);')
                lines.append('        }')
            if trace_return:
                lines.append('        var ret = this.' + target_method + '.apply(this, arguments);')
                lines.append('        console.log("[*] ' + target_method + ' returned: " + ret);')
                lines.append('        return ret;')
            else:
                lines.append('        return this.' + target_method + '.apply(this, arguments);')
            lines.append('    };')
            if verbose:
                lines.append('    console.log("[+] Hooked ' + cls_path + '.' + target_method + '");')
        else:
            # Hook all methods - need to enumerate
            lines.append(f'    var targetClass = Java.use("{cls_path}");')
            lines.append(f'    var methods = targetClass.class.getDeclaredMethods();')
            lines.append('    methods.forEach(function(method) {')
            lines.append('        var methodName = method.getName();')
            lines.append('        try {')
            lines.append('            targetClass[methodName].implementation = function() {')
            lines.append('                console.log("[*] " + methodName + " called");')
            lines.append('                for (var i = 0; i < arguments.length; i++) {')
            lines.append('                    console.log("    arg[" + i + "]: " + arguments[i]);')
            lines.append('                }')
            lines.append('                var ret = this[methodName].apply(this, arguments);')
            lines.append('                console.log("    return: " + ret);')
            lines.append('                return ret;')
            lines.append('            };')
            lines.append('        } catch(e) {')
            lines.append('            // Overloaded or native method')
            lines.append('        }')
            lines.append('    });')
            if verbose:
                lines.append('    console.log("[+] Hooked all methods in ' + cls_path + '");')

        lines.append('});')
        return '\n'.join(lines)

    @staticmethod
    def _frida_bypass_root():
        return [
            '    // ── Root检测绕过 ──',
            '    var rootChecks = ["su", "/system/bin/su", "/system/xbin/su",',
            '                      "/sbin/su", "/system/app/Superuser.apk",',
            '                      "test-keys", "magisk"];',
            '    rootChecks.forEach(function(check) {',
            '        try {',
            '            var File = Java.use("java.io.File");',
            '            File.exists.implementation = function() {',
            '                var path = this.getAbsolutePath();',
            '                if (path && path.indexOf(check) >= 0) return false;',
            '                return this.exists();',
            '            };',
            '        } catch(e) {}',
            '    });',
            '    try {',
            '        var Runtime = Java.use("java.lang.Runtime");',
            '        Runtime.exec.overload("java.lang.String").implementation = function(cmd) {',
            '            if (cmd && (cmd.indexOf("su") >= 0 || cmd.indexOf("which") >= 0)) {',
            '                console.log("[*] Blocked root check: " + cmd);',
            '                throw new Error("blocked");',
            '            }',
            '            return this.exec(cmd);',
            '        };',
            '    } catch(e) {}',
        ]

    @staticmethod
    def _frida_bypass_debug():
        return [
            '    // ── 反调试绕过 ──',
            '    try {',
            '        var Debug = Java.use("android.os.Debug");',
            '        Debug.isDebuggerConnected.implementation = function() {',
            '            return false;',
            '        };',
            '    } catch(e) {}',
        ]

    @staticmethod
    def _frida_bypass_ssl():
        return [
            '    // ── SSL Pinning绕过 ──',
            '    try {',
            '        var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");',
            '        var SSLContext = Java.use("javax.net.ssl.SSLContext");',
            '        var TrustManager = Java.registerClass({',
            '            name: "org.wooyun.TrustAllManager",',
            '            implements: [X509TrustManager],',
            '            methods: {',
            '                checkClientTrusted: function(chain, authType) {}',
            '                , checkServerTrusted: function(chain, authType) {}',
            '                , getAcceptedIssuers: function() { return []; }',
            '            }',
            '        });',
            '        SSLContext.init.overload(',
            '            "[Ljavax.net.ssl.KeyManager;",',
            '            "[Ljavax.net.ssl.TrustManager;",',
            '            "java.security.SecureRandom"',
            '        ).implementation = function(km, tm, sr) {',
            '            this.init(km, [TrustManager.$new()], sr);',
            '        };',
            '    } catch(e) {}',
            '    try {',
            '        var HostnameVerifier = Java.use("javax.net.ssl.HostnameVerifier");',
            '        var HV = Java.registerClass({',
            '            name: "org.wooyun.AllowAll",',
            '            implements: [HostnameVerifier],',
            '            methods: {',
            '                verify: function(hostname, session) { return true; }',
            '            }',
            '        });',
            '        var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");',
            '        HttpsURLConnection.setDefaultHostnameVerifier(HV.$new());',
            '    } catch(e) {}',
        ]

    @staticmethod
    def _frida_bypass_signature():
        return [
            '    // ── 签名校验绕过 ──',
            '    try {',
            '        var PackageManager = Java.use("android.app.PackageManager");',
            '        PackageManager.getPackageInfo.overload("java.lang.String", "int").implementation = function(name, flags) {',
            '            if ((flags & 64) != 0) { // GET_SIGNATURES',
            '                var pkgInfo = this.getPackageInfo(name, flags & ~64);',
            '                // Return fake signatures if needed',
            '                return pkgInfo;',
            '            }',
            '            return this.getPackageInfo(name, flags);',
            '        };',
            '    } catch(e) {}',
        ]

    @staticmethod
    def _frida_bypass_emulator():
        return [
            '    // ── 模拟器检测绕过 ──',
            '    try {',
            '        var Build = Java.use("android.os.Build");',
            '        Build.MODEL.value = "Pixel 6";',
            '        Build.MANUFACTURER.value = "Google";',
            '        Build.BRAND.value = "google";',
            '        Build.PRODUCT.value = "oriole";',
            '        Build.FINGERPRINT.value = "google/oriole/oriole:12/SQ3A.220705.003_A1/8858787:user/release-keys";',
            '    } catch(e) {}',
            '    try {',
            '        var SystemProperties = Java.use("android.os.SystemProperties");',
            '        SystemProperties.get.overload("java.lang.String").implementation = function(key) {',
            '            if (key === "ro.kernel.qemu" || key === "ro.hardware") {',
            '                return "unknown";',
            '            }',
            '            return this.get(key);',
            '        };',
            '    } catch(e) {}',
        ]

    @staticmethod
    def generate_xposed_module(package_name, target_class, target_method=None,
                               bypass_flags=None):
        """生成Xposed模块代码"""
        if target_class.startswith('L') and target_class.endswith(';'):
            cls_path = target_class[1:-1].replace('/', '.')
        else:
            cls_path = target_class.replace('/', '.').replace('L', '').replace(';', '')

        lines = [
            '// Auto-generated Xposed Module',
            '// Package: ' + package_name,
            '// Target Class: ' + cls_path,
            '',
            'package com.auto.hook;',
            '',
            'import de.robv.android.xposed.IXposedHookLoadPackage;',
            'import de.robv.android.xposed.XC_MethodHook;',
            'import de.robv.android.xposed.XposedBridge;',
            'import de.robv.android.xposed.XposedHelpers;',
            'import de.robv.android.xposed.callbacks.XC_LoadPackage;',
            '',
            'public class MainHook implements IXposedHookLoadPackage {',
            '    @Override',
            '    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) throws Throwable {',
            f'        if (!lpparam.packageName.equals("{package_name}")) return;',
            '',
        ]

        if bypass_flags:
            if bypass_flags.get('root'):
                lines.extend(HookGenerator._xposed_bypass_root())
            if bypass_flags.get('debug'):
                lines.extend(HookGenerator._xposed_bypass_debug())

        if target_method:
            lines.append(f'        XposedHelpers.findAndHookMethod("{cls_path}",')
            lines.append(f'            lpparam.classLoader, "{target_method}",')
            lines.append('            new XC_MethodHook() {')
            lines.append('                @Override')
            lines.append('                protected void beforeHookedMethod(MethodHookParam param) {')
            lines.append('                    XposedBridge.log("[*] ' + target_method + ' called");')
            lines.append('                    for (Object arg : param.args) {')
            lines.append('                        XposedBridge.log("    arg: " + arg);')
            lines.append('                    }')
            lines.append('                }')
            lines.append('                @Override')
            lines.append('                protected void afterHookedMethod(MethodHookParam param) {')
            lines.append('                    XposedBridge.log("    return: " + param.getResult());')
            lines.append('                }')
            lines.append('            });')
        else:
            lines.append(f'        Class<?> targetClass = XposedHelpers.findClass("{cls_path}", lpparam.classLoader);')
            lines.append('        for (java.lang.reflect.Method m : targetClass.getDeclaredMethods()) {')
            lines.append('            XposedBridge.hookMethod(m, new XC_MethodHook() {')
            lines.append('                @Override')
            lines.append('                protected void beforeHookedMethod(MethodHookParam param) {')
            lines.append('                    XposedBridge.log("[*] " + param.method.getName() + " called");')
            lines.append('                }')
            lines.append('            });')
            lines.append('        }')

        lines.append('    }')
        lines.append('}')
        return '\n'.join(lines)

    @staticmethod
    def _xposed_bypass_root():
        return [
            '        // Root bypass',
            '        XposedHelpers.findAndHookMethod("java.io.File", lpparam.classLoader,',
            '            "exists", new XC_MethodHook() {',
            '                @Override',
            '                protected void afterHookedMethod(MethodHookParam param) {',
            '                    String path = ((java.io.File) param.thisObject).getAbsolutePath();',
            '                    if (path.contains("su") || path.contains("magisk") || path.contains("superuser")) {',
            '                        param.setResult(false);',
            '                    }',
            '                }',
            '            });',
        ]

    @staticmethod
    def _xposed_bypass_debug():
        return [
            '        // Anti-debug bypass',
            '        XposedHelpers.findAndHookMethod("android.os.Debug", lpparam.classLoader,',
            '            "isDebuggerConnected", new XC_MethodHook() {',
            '                @Override',
            '                protected void afterHookedMethod(MethodHookParam param) {',
            '                    param.setResult(false);',
            '                }',
            '            });',
        ]

    @staticmethod
    def generate_smali_patch(target_class, target_method, patch_type='bypass_return',
                              return_value='0x0'):
        """生成smali补丁代码片段"""
        if target_class.startswith('L') and target_class.endswith(';'):
            smali_class = target_class
        else:
            smali_class = 'L' + target_class.replace('.', '/') + ';'

        if patch_type == 'bypass_return':
            return f'''.method public {target_method}()I
    # Patched: bypass return value
    const/4 v0, {return_value}
    return v0
.end method'''
        elif patch_type == 'log_only':
            return f'''.method public {target_method}()I
    # Patched: log and continue
    const-string v0, "HOOK"
    const-string v1, "{target_method} called"
    invoke-static {{v0, v1}}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I
    const/4 v0, {return_value}
    return v0
.end method'''
        elif patch_type == 'nop':
            return f'''.method public {target_method}()V
    # Patched: NOP (do nothing)
    return-void
.end method'''
        return ''