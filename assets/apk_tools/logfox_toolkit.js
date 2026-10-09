/*
METADATA
{
"name": "logfox_toolkit",
"display_name": {
"zh": "日志/崩溃分析工具包",
"en": "LogFox Crash Analyzer"
},
"description": "复刻开源 LogFox 崩溃解析逻辑的日志/崩溃分析工具包（Operit 逆向工作流内置）：logcat 后台录制、crash 缓冲读取、Java 崩溃（AndroidRuntime/FATAL EXCEPTION）、Native 崩溃（DEBUG/*** ***）、libc Fatal signal 兜底、ANR（am_anr 事件）解析，以及 APK 启动冒烟测试（自动解析 MAIN/LAUNCHER 入口→启动→存活/崩溃/前台 Activity 检查）。全部在 Android 侧 shell 执行，JS 侧解析，无需 Python。",
"category": "ReverseEngineering",
"tools": [
{
"name": "log_capture_start",
"description": "启动后台 logcat 录制（threadtime 格式，默认 main+crash 缓冲），PID 存 /sdcard/Download/.lf_capture.pid，输出到指定文件。用于长时间采集应用运行日志（如冒烟测试、复现崩溃）。",
"parameters": [
{ "name": "buffers", "description": "逗号分隔的缓冲列表，默认 main,crash（可选 system/events）", "type": "string", "required": false },
{ "name": "out", "description": "输出文件路径，默认 /sdcard/Download/logfox_capture.log", "type": "string", "required": false }
]
},
{
"name": "log_capture_stop",
"description": "停止后台 logcat 录制并清理 PID 文件，返回录制统计（文件大小等）。",
"parameters": []
},
{
"name": "log_read_crash",
"description": "读取 Android crash 缓冲（logcat -d -b crash -t N）并全量解析：Java 崩溃 + Native 崩溃 + libc Fatal signal。返回结构化数据 + 人类可读摘要，支持按包名过滤。",
"parameters": [
{ "name": "tail", "description": "读取行数，默认 500", "type": "number", "required": false },
{ "name": "pkg", "description": "可选包名过滤（如 com.fenbi.android.zhaojiao）", "type": "string", "required": false }
]
},
{
"name": "log_parse_java_crash",
"description": "解析 Java 崩溃：复刻 LogFox JavaCrashDataSource（tag=AndroidRuntime 且 FATAL EXCEPTION 开头，第二行 Process 取包名，提取异常类/消息/堆栈/崩溃点）。输入 logcat 文本（text 参数）或 Android 侧文件（file 参数）。",
"parameters": [
{ "name": "text", "description": "直接传 logcat 文本内容（与 file 二选一）", "type": "string", "required": false },
{ "name": "file", "description": "Android 侧日志文件路径（与 text 二选一）", "type": "string", "required": false }
]
},
{
"name": "log_parse_native_crash",
"description": "解析 Native 崩溃：复刻 LogFox JNICrashDataSource（tag=DEBUG 且 *** *** 开头，>>> pkg <<< 取包名，signal 行取信号，fault addr/ABI/backtrace 回溯），并附带 libc Fatal signal 事件兜底解析。输入 logcat 文本或文件。",
"parameters": [
{ "name": "text", "description": "直接传 logcat 文本内容（与 file 二选一）", "type": "string", "required": false },
{ "name": "file", "description": "Android 侧日志文件路径（与 text 二选一）", "type": "string", "required": false }
]
},
{
"name": "log_analyze_anr",
"description": "分析 ANR：读取 events 缓冲（logcat -d -b events -t N）严格匹配 am_anr:[user,pid,pkg,reason] 事件（消除正文误报），返回 ANR 列表与原因。",
"parameters": [
{ "name": "tail", "description": "读取 events 行数，默认 2000", "type": "number", "required": false },
{ "name": "file", "description": "可选：events 缓冲已导出文件路径（不传则实时读取）", "type": "string", "required": false }
]
},
{
"name": "apk_launch_test",
"description": "APK 启动冒烟测试：清 logcat(crash+main) → 自动解析 MAIN/LAUNCHER 入口（cmd package resolve-activity）→ am start 启动 → 等待 N 秒 → pidof 查进程存活 → 读 crash 缓冲查崩溃 → dumpsys 查前台 Activity。target 传包名或 APK 路径；传 APK 路径时自动 pm install -r（Android 13+ 若安装失败请先 cp 到 /data/local/tmp/ 再装）。",
"parameters": [
{ "name": "target", "description": "包名（如 com.fenbi.android.zhaojiao）或 APK 路径", "type": "string", "required": true },
{ "name": "activity", "description": "可选：显式指定 Activity（如 WelcomeActivity），不传自动解析 LAUNCHER", "type": "string", "required": false },
{ "name": "wait", "description": "启动后等待秒数，默认 8", "type": "number", "required": false }
]
}
]
}
*/
// ============================================================
// LogFox 日志/崩溃分析工具包 v1.0（复刻 F0x1d/LogFox 解析逻辑）
// 1. Android 侧 shell 采集：logcat / am / pm / dumpsys / pidof
// 2. JS 侧解析：Java 崩溃 / Native 崩溃 / libc 信号 / ANR
// 3. 内置 APK 启动冒烟测试（自动解析 MAIN/LAUNCHER 入口）
// ============================================================
var logfox = (function () {
    'use strict';

    var CAPTURE_PID_FILE = '/sdcard/Download/.lf_capture.pid';
    var DEFAULT_OUT = '/sdcard/Download/logfox_capture.log';

    function wrap(fn) {
        return function (params) {
            return Promise.resolve()
                .then(function () { return fn(params || {}); })
                .then(function (result) { return { success: true, data: result }; })
                .catch(function (err) {
                    return { success: false, message: (err && err.message) ? err.message : String(err) };
                });
        };
    }

    function shellQuote(s) {
        return "'" + String(s).replace(/'/g, "'\\''") + "'";
    }

    // Android 侧 shell 执行（Tools.System.shell，需 root/Shizuku 通道）
    function shellExec(cmd) {
        return Promise.resolve()
            .then(function () { return Tools.System.shell(cmd); })
            .then(function (r) {
                return { ok: true, output: (r && r.output) ? r.output : '' };
            })
            .catch(function (err) {
                return { ok: false, output: (err && err.message) ? err.message : String(err) };
            });
    }

    // ---------- logcat 行格式 ----------
    var LOGCAT_RE = /^(\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})\s+(\d+)\s+(\d+)\s+([VDIWEF])\s+(\S+?)\s*:\s?(.*)$/;

    // ---------- Java 崩溃（复刻 JavaCrashDataSource） ----------
    var JAVA_CRASH_RE = /^FATAL EXCEPTION:\s*(.*)$/;
    var PROCESS_RE = /^Process:\s*(\S+),\s*PID:\s*(\d+)$/;
    var EXCEPTION_RE = /^([\w.$]+?)(?::\s*(.*))?$/;

    function parseJavaCrashes(lines) {
        var crashes = [];
        var cur = null;
        for (var i = 0; i < lines.length; i++) {
            var raw = lines[i];
            var line = raw.replace(/\r?\n$/, '');
            var m = LOGCAT_RE.exec(line);
            if (m) {
                var ts = m[1], pid = m[2], lvl = m[4], tag = m[5], content = m[6];
                if (tag === 'AndroidRuntime' && content.indexOf('FATAL EXCEPTION: ') === 0) {
                    var jm = JAVA_CRASH_RE.exec(content);
                    cur = {
                        type: 'java',
                        thread: jm ? jm[1] : content,
                        timestamp: ts,
                        pid: pid,
                        package: null,
                        exception: null,
                        message: null,
                        stack: []
                    };
                    crashes.push(cur);
                    continue;
                }
                if (cur) {
                    if (tag !== 'AndroidRuntime') {
                        cur = null;
                        continue;
                    }
                    var pm = PROCESS_RE.exec(content);
                    if (pm && cur.package === null) {
                        cur.package = pm[1];
                        cur.pid = pm[2];
                        continue;
                    }
                    if (cur.exception === null && content &&
                        content.indexOf('\t') !== 0 && content.indexOf('at ') !== 0 &&
                        content.indexOf('Caused by') !== 0 && content.indexOf('Suppressed') !== 0) {
                        var em = EXCEPTION_RE.exec(content);
                        if (em && em[1] && em[1].indexOf('.') !== -1) {
                            cur.exception = em[1];
                            cur.message = em[2] ? em[2] : null;
                            cur.stack.push(line);
                            continue;
                        }
                    }
                    cur.stack.push(line);
                }
            } else {
                if (cur && line.indexOf('---------') !== 0) {
                    cur.stack.push(line);
                }
            }
        }
        return crashes;
    }

    // ---------- Native 崩溃（复刻 JNICrashDataSource） ----------
    var NATIVE_HEADER_RE = /^\*\*\* \*\*\*/;
    var PACKAGE_RE = />>>\s*(\S+?)\s*<</;
    var SIGNAL_RE = /^signal\s+(\d+)\s+\((\S+)\)/;
    var BT_RE = /^\s*#\d+/;

    function parseNativeCrashes(lines) {
        var crashes = [];
        var cur = null;
        for (var i = 0; i < lines.length; i++) {
            var raw = lines[i];
            var line = raw.replace(/\r?\n$/, '');
            var m = LOGCAT_RE.exec(line);
            if (m) {
                var ts = m[1], pid = m[2], lvl = m[4], tag = m[5], content = m[6];
                if (tag === 'DEBUG' && NATIVE_HEADER_RE.exec(content)) {
                    cur = {
                        type: 'native',
                        timestamp: ts,
                        pid: pid,
                        package: null,
                        signal: null,
                        signal_name: null,
                        fault_addr: null,
                        abi: null,
                        backtrace: [],
                        raw: [line]
                    };
                    crashes.push(cur);
                    continue;
                }
                if (cur) {
                    cur.raw.push(line);
                    var pm = PACKAGE_RE.exec(content);
                    if (pm && cur.package === null) {
                        cur.package = pm[1];
                        continue;
                    }
                    var sm = SIGNAL_RE.exec(content);
                    if (sm) {
                        cur.signal = parseInt(sm[1], 10);
                        cur.signal_name = sm[2];
                        continue;
                    }
                    if (content.indexOf('fault addr') === 0) {
                        cur.fault_addr = content;
                        continue;
                    }
                    if (content.indexOf('ABI') === 0) {
                        cur.abi = content;
                        continue;
                    }
                    if (BT_RE.exec(content)) {
                        cur.backtrace.push(content);
                    }
                }
            } else {
                if (cur) {
                    cur.raw.push(line);
                }
            }
        }
        return crashes;
    }
    // ---------- libc Fatal signal 事件（crash_dump 失败时的兜底） ----------
    var LIBC_SIGNAL_RE = /^Fatal signal\s+(\d+)\s+\((\S+)\),\s+code\s+(\S+)\s+\((\S+)\)\s+in tid\s+(\d+)\s+\((\S+)\),\s+pid\s+(\d+)\s+\((\S+)\)/;

    function parseLibcSignals(lines) {
        var events = [];
        for (var i = 0; i < lines.length; i++) {
            var line = lines[i].replace(/\r?\n$/, '');
            var m = LOGCAT_RE.exec(line);
            if (!m) continue;
            var ts = m[1], tag = m[5], content = m[6];
            if (tag === 'libc' && content.indexOf('Fatal signal') === 0) {
                var sm = LIBC_SIGNAL_RE.exec(content);
                if (sm) {
                    events.push({
                        timestamp: ts,
                        pid: sm[7],
                        tid: sm[5],
                        thread_name: sm[6],
                        proc_name: sm[8],
                        signal: parseInt(sm[1], 10),
                        signal_name: sm[2],
                        code: sm[3],
                        code_name: sm[4],
                        raw: line
                    });
                }
            }
        }
        return events;
    }

    // ---------- ANR（events buffer am_anr，严格要求 [ 数据块） ----------
    var ANR_EVENT_RE = /am_anr\s*:\s*\[(\d+),(\d+),(\S+),(.*?)\]/;

    function parseAnr(lines) {
        var anrs = [];
        for (var i = 0; i < lines.length; i++) {
            var line = lines[i].replace(/\r?\n$/, '');
            var m = ANR_EVENT_RE.exec(line);
            if (!m) continue;
            anrs.push({
                user: m[1],
                pid: m[2],
                package: m[3],
                reason: m[4],
                raw: line
            });
        }
        return anrs;
    }

    function parseAll(lines) {
        return {
            java_crashes: parseJavaCrashes(lines),
            native_crashes: parseNativeCrashes(lines),
            libc_signals: parseLibcSignals(lines)
        };
    }

    function filterByPkg(result, pkg) {
        if (!pkg) return result;
        var out = {};
        ['java_crashes', 'native_crashes'].forEach(function (k) {
            out[k] = (result[k] || []).filter(function (c) {
                return (c.package || '').indexOf(pkg) !== -1;
            });
        });
        out.libc_signals = (result.libc_signals || []).filter(function (e) {
            return (e.proc_name || '').indexOf(pkg) !== -1;
        });
        return out;
    }

    function bizFrame(stack) {
        for (var i = 0; i < stack.length; i++) {
            var s = stack[i];
            if (s.indexOf('\tat ') !== -1 &&
                s.indexOf('android.') === -1 && s.indexOf('java.') === -1 &&
                s.indexOf('kotlin.') === -1 && s.indexOf('dalvik.') === -1 &&
                s.indexOf('com.android.') === -1) {
                var parts = s.split('at ', 2);
                return parts[1] ? parts[1].trim() : s.trim();
            }
        }
        return null;
    }

    function compactSummary(result) {
        var out = [];
        var jc = result.java_crashes || [];
        var nc = result.native_crashes || [];
        var lc = result.libc_signals || [];
        var an = result.anrs || [];

        if (jc.length) {
            out.push('═══ Java 崩溃 (' + jc.length + ') ═══');
            jc.forEach(function (c) {
                out.push('  [' + c.timestamp + '] ' + (c.exception || '?'));
                out.push('    线程: ' + c.thread + '  包: ' + (c.package || '?') + '  PID: ' + c.pid);
                if (c.message) out.push('    消息: ' + c.message.substring(0, 200));
                var bf = bizFrame(c.stack);
                if (bf) out.push('    崩溃点: ' + bf);
                out.push('');
            });
        }
        if (nc.length) {
            out.push('═══ Native 崩溃 (' + nc.length + ') ═══');
            nc.forEach(function (c) {
                var sig = c.signal ? (c.signal_name + '(' + c.signal + ')') : '?';
                out.push('  [' + c.timestamp + '] ' + sig);
                out.push('    包: ' + (c.package || '?') + '  PID: ' + c.pid + '  ' + (c.abi || ''));
                if (c.fault_addr) out.push('    ' + c.fault_addr);
                if (c.backtrace.length) {
                    out.push('    回溯: ' + c.backtrace[0]);
                    if (c.backtrace.length > 1) out.push('          ' + c.backtrace[1]);
                }
                out.push('');
            });
        }
        if (lc.length) {
            out.push('═══ libc Fatal signal (' + lc.length + ') ═══');
            lc.forEach(function (e) {
                out.push('  [' + e.timestamp + '] ' + e.signal_name + '(' + e.signal + ') ' +
                    e.code_name + ' 进程: ' + (e.proc_name || '?') + ' pid=' + e.pid + ' tid=' + e.tid);
            });
        }
        if (an.length) {
            out.push('═══ ANR (' + an.length + ') ═══');
            an.forEach(function (e) {
                out.push('  ' + (e.package || '?') + ' 原因: ' + String(e.reason || e.raw || '').substring(0, 150));
            });
        }
        if (!jc.length && !nc.length && !lc.length && !an.length) {
            out.push('未发现崩溃/ANR 记录');
        }
        return out.join('\n');
    }
    // ========== 工具1: log_capture_start ==========
    function log_capture_start(params) {
        var buffers = params.buffers || 'main,crash';
        var out = params.out || DEFAULT_OUT;
        var bufArgs = buffers.split(',').map(function (b) {
            return '-b ' + b.trim();
        }).join(' ');
        var script = 'logcat -v threadtime ' + bufArgs + ' > ' + out + ' 2>&1 &\n' +
            'echo $! > ' + CAPTURE_PID_FILE + '\n' +
            'sleep 1; echo "--- PID ---"; cat ' + CAPTURE_PID_FILE + '; echo; echo "--- 输出文件 ---"; ls -la ' + out;
        return shellExec(script).then(function (r) {
            var pid = null;
            var m = /--- PID ---\s*\n(\d+)/.exec(r.output);
            if (m) pid = m[1];
            return {
                started: r.ok,
                pid: pid,
                buffers: buffers,
                out: out,
                pidFile: CAPTURE_PID_FILE,
                detail: r.output
            };
        });
    }

    // ========== 工具2: log_capture_stop ==========
    function log_capture_stop() {
        var script = 'if [ -f ' + CAPTURE_PID_FILE + ' ]; then PID=$(cat ' + CAPTURE_PID_FILE + '); ' +
            'kill $PID 2>/dev/null; echo "killed $PID"; rm -f ' + CAPTURE_PID_FILE + '; ' +
            'else echo "no capture running"; fi; echo "--- 录制文件 ---"; ' +
            'ls -la ' + DEFAULT_OUT + ' 2>/dev/null; ls -la ' + '/sdcard/Download/logfox_capture*.log 2>/dev/null; true';
        return shellExec(script).then(function (r) {
            return {
                stopped: r.ok,
                detail: r.output
            };
        });
    }

    // ========== 工具3: log_read_crash ==========
    function log_read_crash(params) {
        var tail = params.tail || 500;
        var pkg = params.pkg || null;
        return shellExec('logcat -d -b crash -t ' + tail + ' 2>/dev/null').then(function (r) {
            var lines = r.output.split('\n');
            var result = parseAll(lines);
            if (pkg) result = filterByPkg(result, pkg);
            var summary = compactSummary(result);
            return {
                tail: tail,
                pkg: pkg,
                total_lines: lines.length,
                java_count: result.java_crashes.length,
                native_count: result.native_crashes.length,
                libc_count: result.libc_signals.length,
                crashes: result,
                summary: summary
            };
        });
    }

    // ========== 工具4: log_parse_java_crash ==========
    function log_parse_java_crash(params) {
        var text = params.text;
        var file = params.file;
        var p = text ? Promise.resolve(text) :
            (file ? shellExec('cat ' + shellQuote(file) + ' 2>/dev/null').then(function (r) { return r.output; }) :
             Promise.reject(new Error('需传 text 或 file 参数')));
        return p.then(function (content) {
            var lines = content.split('\n');
            var crashes = parseJavaCrashes(lines);
            return {
                count: crashes.length,
                crashes: crashes,
                summary: compactSummary({ java_crashes: crashes })
            };
        });
    }

    // ========== 工具5: log_parse_native_crash ==========
    function log_parse_native_crash(params) {
        var text = params.text;
        var file = params.file;
        var p = text ? Promise.resolve(text) :
            (file ? shellExec('cat ' + shellQuote(file) + ' 2>/dev/null').then(function (r) { return r.output; }) :
             Promise.reject(new Error('需传 text 或 file 参数')));
        return p.then(function (content) {
            var lines = content.split('\n');
            var natives = parseNativeCrashes(lines);
            var libc = parseLibcSignals(lines);
            return {
                native_count: natives.length,
                libc_count: libc.length,
                native_crashes: natives,
                libc_signals: libc,
                summary: compactSummary({ native_crashes: natives, libc_signals: libc })
            };
        });
    }
        // ========== 工具6: log_analyze_anr ==========
    function log_analyze_anr(params) {
        var tail = params.tail || 2000;
        var file = params.file;
        var text = params.text;
        var p = text ? Promise.resolve(text) :
            (file ? shellExec('cat ' + shellQuote(file) + ' 2>/dev/null').then(function (r) { return r.output; }) :
             shellExec('logcat -d -b events -t ' + tail + ' 2>/dev/null').then(function (r) { return r.output; }));
        return p.then(function (content) {
            var lines = content.split('\n');
            var anrs = parseAnr(lines);
            return {
                count: anrs.length,
                source: text ? '(text)' : (file || ('events buffer (tail ' + tail + ')')),
                anrs: anrs,
                summary: compactSummary({ anrs: anrs })
            };
        });
    }

    // ========== 工具7: apk_launch_test ==========
    function apk_launch_test(params) {
        var target = params.target;
        if (!target) return Promise.reject(new Error('缺少 target（包名或 APK 路径）'));
        var activity = params.activity || null;
        var wait = params.wait || 8;
        var pkg = target;
        var lines = [];
        lines.push('logcat -c -b crash -b main 2>/dev/null; logcat -c 2>/dev/null');
        if (target.indexOf('.apk') !== -1) {
            lines.push('pm install -r ' + shellQuote(target) + ' 2>&1 | tail -1');
            pkg = null;
        } else {
            lines.push('am force-stop ' + pkg + ' 2>/dev/null; sleep 1');
        }
        if (pkg) {
            if (!activity) {
                lines.push('LAUNCHER=$(cmd package resolve-activity --brief -a android.intent.action.MAIN ' +
                    '-c android.intent.category.LAUNCHER ' + pkg + ' 2>/dev/null | tail -1 | tr -d "\\r")');
                lines.push('if echo "$LAUNCHER" | grep -q "/"; then am start -n "$LAUNCHER" 2>&1; ' +
                    'else am start -a android.intent.action.MAIN -c android.intent.category.LAUNCHER -p ' + pkg + ' 2>&1; fi');
            } else {
                var act = activity.indexOf('.') === 0 ? activity : '.' + activity;
                lines.push('am start -n ' + pkg + '/' + act + ' 2>&1');
            }
            lines.push('sleep ' + wait);
            lines.push('echo "--- 进程状态 ---"; pidof ' + pkg + ' && echo "存活 OK" || echo "已退出 FAIL"');
            lines.push('echo "--- crash 缓冲 ---"; logcat -d -b crash -t 200 2>/dev/null | tail -100');
            lines.push('echo "--- 最近 FATAL/ANR ---"; logcat -d -t 300 2>/dev/null | ' +
                'grep -v "SHELLOUT" | grep -E "FATAL EXCEPTION|AndroidRuntime|Process .* died|am_anr|ANR in " | tail -20');
            lines.push('echo "--- 前台 Activity ---"; dumpsys activity activities 2>/dev/null | ' +
                'grep -E "topResumedActivity|mResumedActivity" | head -3');
        }
        var script = lines.join('\n');
        return shellExec(script).then(function (r) {
            var out = r.output;
            var alive = false;
            var mAlive = /存活 OK/.exec(out);
            if (mAlive) alive = true;
            var fatalCount = 0;
            // 排除工具自身 echo 的标记行（含 FATAL/ANR 字样），只统计真实崩溃
            var cleanOut = out.replace(/--- .* ---/g, '');
            var mFatal = cleanOut.match(/FATAL EXCEPTION|AndroidRuntime|FATAL: |Fatal signal/g);
            if (mFatal) fatalCount = mFatal.length;
            return {
                target: target,
                activity: activity || '(auto LAUNCHER)',
                wait_seconds: wait,
                alive: alive,
                output: out,
                note: alive ? '进程存活，冒烟通过' : '进程退出/未检测到，需查看输出与 crash 缓冲'
            };
        });
    }

    return {
        log_capture_start: wrap(log_capture_start),
        log_capture_stop: wrap(log_capture_stop),
        log_read_crash: wrap(log_read_crash),
        log_parse_java_crash: wrap(log_parse_java_crash),
        log_parse_native_crash: wrap(log_parse_native_crash),
        log_analyze_anr: wrap(log_analyze_anr),
        apk_launch_test: wrap(apk_launch_test)
    };
})();
exports.log_capture_start = logfox.log_capture_start;
exports.log_capture_stop = logfox.log_capture_stop;
exports.log_read_crash = logfox.log_read_crash;
exports.log_parse_java_crash = logfox.log_parse_java_crash;
exports.log_parse_native_crash = logfox.log_parse_native_crash;
exports.log_analyze_anr = logfox.log_analyze_anr;
exports.apk_launch_test = logfox.apk_launch_test;