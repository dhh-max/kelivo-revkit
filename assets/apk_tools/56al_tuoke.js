/*
METADATA
{
"name": "56al_tuoke",
"display_name": {
"zh": "脱壳修复工具包",
"en": "Unpack & Dex Repair Toolkit"
},
"description": "基于 56.al 在线脱壳的一体化脱壳+修复工具包：上传 APK 云端自动脱壳，下载后用 dexlib2 引擎（与 MT 管理器同源）规范化修复 dex（重算 checksum/SHA-1、字符串去重、数据段重排，等价 MT 的 dex 修复）。首次使用：tuoke_login_url 获取授权链接→浏览器登录→tuoke_set_cookie 粘贴 Cookie（或 tuoke_browser_login 自动读取），登录态持久化自动复用。tuoke_all 一键完成上传→脱壳→下载→自动修复全流程。",
"category": "ReverseEngineering",
"tools": [
{
"name": "tuoke_login_url",
"description": "获取 56.al 第三方 OAuth 授权登录链接（github/qq/gitee/microsoft/wx）。浏览器打开完成授权后，从浏览器复制 Cookie 并调用 tuoke_set_cookie 完成包内登录。",
"parameters": [
{ "name": "provider", "description": "OAuth 提供方: github / qq / gitee / microsoft / wx，默认 github", "type": "string", "required": false }
]
},
{
"name": "tuoke_browser_login",
"description": "从 Operit 内置浏览器自动读取 56.al 登录 Cookie 并保存（用户只需先在浏览器里打开 56.al 完成登录）。自动验证登录态。零门槛，无需手动复制 Cookie。",
"parameters": [
{ "name": "open_login_page", "description": "true=自动打开 56.al 登录页（默认 true）", "type": "boolean", "required": false }
]
},
{
"name": "tuoke_set_cookie",
"description": "设置并持久化 56.al 登录 Cookie（保存到本地，之后所有上传请求自动携带）。接受完整 Cookie 字符串（如 PHPSESSID=abc123...），立即调用 pre_upload 验证登录态是否有效。",
"parameters": [
{ "name": "cookie", "description": "登录后的 Cookie 字符串，例如 PHPSESSID=xxxx（可含多个键值对，用分号分隔）", "type": "string", "required": true }
]
},
{
"name": "tuoke_get_cookie",
"description": "查看当前已保存的 56.al Cookie 摘要（脱敏显示），并验证登录态是否有效。",
"parameters": []
},
{
"name": "tuoke_clear_cookie",
"description": "清除本地保存的 56.al 登录 Cookie。",
"parameters": []
},
{
"name": "tuoke_upload",
"description": "上传 APK 到 56.al 云脱壳（≤8MB，小包适用）。返回任务 hash。大 APK 请用 tuoke_upload_big。需要先登录。",
"parameters": [
{ "name": "apk_path", "description": "待脱壳 APK 的 Android 路径", "type": "string", "required": true },
{ "name": "csrf_token", "description": "56.al 上传页的 csrf_token（可选，默认自动获取）", "type": "string", "required": false }
]
},
{
"name": "tuoke_upload_big",
"description": "上传大 APK（>8MB）到 56.al：Linux 侧流式算 MD5，分片上传。返回任务 hash。需要先登录。",
"parameters": [
{ "name": "apk_path", "description": "待脱壳 APK 的 Android 路径", "type": "string", "required": true },
{ "name": "csrf_token", "description": "56.al 上传页的 csrf_token（可选，默认自动获取）", "type": "string", "required": false }
]
},
{
"name": "tuoke_status",
"description": "查询 56.al 脱壳任务状态（无需登录）。返回任务日志与状态(success/error/processing)。",
"parameters": [
{ "name": "hash", "description": "任务 hash（32位MD5）", "type": "string", "required": true },
{ "name": "since_id", "description": "上次已读日志ID，用于增量查询，默认0", "type": "number", "required": false }
]
},
{
"name": "tuoke_download",
"description": "下载 56.al 脱壳结果 7z 并自动解压 + 修复 dex 头（无需登录）。默认输出到 APK 同目录下新建的「<软件名>脱壳文件」文件夹（需传 apk_path 才能自动定位；否则输出到 /sdcard/Download/Operit/tuoke_out/{hash}）。大文件 Linux 侧流式处理，返回文件路径列表（不返回内容）。",
"parameters": [
{ "name": "hash", "description": "任务 hash", "type": "string", "required": true },
{ "name": "output_dir", "description": "自定义输出目录（默认：apk_path 同目录/<软件名>脱壳文件；无 apk_path 时默认 /sdcard/Download/Operit/tuoke_out/{hash}）", "type": "string", "required": false },
{ "name": "apk_path", "description": "原 APK 路径（用于自动定位输出目录，建议传）", "type": "string", "required": false },
{ "name": "skip_unpack", "description": "true=只下载 7z 不解压", "type": "boolean", "required": false }
]
},
{
"name": "tuoke_all",
"description": "一键云脱壳：上传 → 轮询等待 → 下载+解压+修复 dex 头。产物默认放到 APK 同目录下新建的「<软件名>脱壳文件」文件夹（可传 output_dir 覆盖）。输出文件路径报告。需要先登录。",
"parameters": [
{ "name": "apk_path", "description": "待脱壳 APK 的 Android 路径", "type": "string", "required": true },
{ "name": "output_dir", "description": "自定义输出目录（默认 APK 同目录/<软件名>脱壳文件）", "type": "string", "required": false },
{ "name": "max_wait_seconds", "description": "最大等待秒数（默认1800）", "type": "number", "required": false }
]
},
{
"name": "tuoke_fix_dex",
"description": "修复 dex 文件的 dex 头（魔数/文件大小/头大小）。Linux 侧流式处理，只读头部。",
"parameters": [
{ "name": "dex_path", "description": "dex 文件路径", "type": "string", "required": true },
{ "name": "output_path", "description": "可选，输出路径（默认覆盖原文件）", "type": "string", "required": false }
]
},
{
"name": "tuoke_check_auth",
"description": "检查 56.al 登录态是否有效：读取已保存 Cookie 并调用 pre_upload 验证（403=未登录/过期，200+code=有效）。返回诊断详情与修复指引。",
"parameters": []
},
{
"name": "tuoke_dex_clean",
"description": "用 dexlib2（与 MT 管理器同源引擎）规范化重写 dex：重算 checksum/SHA-1 签名、字符串去重、数据段紧凑重排。等价于 MT 管理器的 dex 修复功能。输入文件或目录，输出到指定目录（默认 <输入目录>/修复dex/）。",
"parameters": [
{ "name": "dex_path", "description": "待修复的 dex 文件路径或包含 dex 的目录", "type": "string", "required": true },
{ "name": "output_dir", "description": "可选，输出目录（默认：dex_path 为目录时输出到 <目录>/修复dex/；为文件时输出到同目录/修复dex/）", "type": "string", "required": false }
]
}
]
}
*/
// ============================================================
// 脱壳修复工具包 v11.1（56.al 在线脱壳 + dexlib2 修复）
// 1. 上传加固 APK 到 56.al 云端脱壳，下载 7z 并解压出 dex
// 2. dexlib2 规范化修复（等价 MT 管理器 dex 修复）
// 3. 全流程 Linux 侧流式处理，根治 OOM
// 4. 内置登录引导 + Cookie 持久化，分享即用
// 5. v11.1: 孤儿任务重建 + complete 前重新抓 csrf（根治新文件卡死）（文件已入库但任务未建时自动补传分片+complete）
// ============================================================
var tuoke56 = (function () {
    'use strict';

    var BASE = 'https://56.al';
    var PASSWORD = 'dump';
    var CHUNK_SIZE = 8388608;
    var COOKIE_FILE = '/sdcard/Download/Operit/tuoke_out/.56al_cookie.b64';

    function dirname(p) {
        if (!p) return '/sdcard/Download/Operit/tuoke_out';
        var i = p.lastIndexOf('/');
        return i > 0 ? p.substring(0, i) : '/';
    }

    // 根据 APK 路径派生默认输出目录：<APK同目录>/<软件名去扩展名>脱壳文件
    // 例如 /sdcard/Download/xxx.apk -> /sdcard/Download/xxx脱壳文件
    function deriveOutDir(apkPath) {
        if (!apkPath) return null;
        var dir = dirname(apkPath);
        var name = apkPath.split('/').pop() || '';
        var base = name.replace(/\.[^.]*$/, '') || 'tuoke';
        return dir + '/' + base + '脱壳文件';
    }

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

    function exec(cmd, timeoutMs) {
        return Tools.System.terminal.hiddenExec(cmd, { timeoutMs: timeoutMs || 300000 })
            .then(function (r) {
                if (!r || r.exitCode !== 0) {
                    var out = (r && r.output) ? r.output : '';
                    var e = new Error('命令执行失败 (exit=' + (r ? r.exitCode : '?') + '): ' + cmd + '\n' + out.substring(0, 800));
                    e.exitCode = r ? r.exitCode : -1;
                    e.output = out;
                    throw e;
                }
                return r;
            });
    }

    function toLinuxPath(p) { return p; }

    function shellQuote(s) {
        return "'" + String(s).replace(/'/g, "'\\''") + "'";
    }

    function respText(resp) {
        return resp.text || resp.content || resp.body || '';
    }

    // ========== Cookie 持久化管理 ==========
    // 内置默认 Cookie（已内嵌进包源码，开箱即用，无需每次重新登录）
    var EMBEDDED_COOKIE = '';
    function ensureDir() {
        return exec('mkdir -p /sdcard/Download/Operit/tuoke_out', 10000);
    }

    function saveCookie(cookie) {
        var raw = String(cookie).trim();
        return ensureDir()
            .then(function () {
                // 用 Linux base64 编码写入（JS 环境可能无 btoa）
                return exec('printf %s ' + shellQuote(raw) + ' | base64 -w0 > ' + shellQuote(COOKIE_FILE) + ' && chmod 600 ' + shellQuote(COOKIE_FILE), 10000);
            });
    }

    function loadCookie() {
        return exec('cat ' + shellQuote(COOKIE_FILE) + ' 2>/dev/null', 10000)
            .then(function (r) {
                var b64 = r.output.trim();
                if (!b64) return EMBEDDED_COOKIE; // 文件不存在/为空时用内嵌 Cookie
                // 用 Linux base64 -d 解码
                return exec('printf %s ' + shellQuote(b64) + ' | base64 -d 2>/dev/null', 10000)
                    .then(function (rr) { return rr.output.trim() || EMBEDDED_COOKIE; })
                    .catch(function () { return EMBEDDED_COOKIE; });
            })
            .catch(function () { return EMBEDDED_COOKIE; });
    }

    function clearCookie() {
        return exec('rm -f ' + shellQuote(COOKIE_FILE), 10000)
            .then(function () { return { cleared: true }; });
    }

    function extractPhpSessId(cookie) {
        if (!cookie) return null;
        var m = cookie.match(/PHPSESSID=([^;\s]+)/i);
        return m ? m[1] : null;
    }

    // ========== 带 Cookie 的请求封装 ==========
    // 注意：Tools.Net.http 会把 Content-Type 强制改为 application/json，
    // 导致 56.al 的 PHP 端 $_POST 解析不到 form 字段（返回 no type / 403）。
    // 因此所有 form POST 统一走 Linux 侧 curl，可靠且不占 JS 内存。

    // curl 执行 form POST，可选带 cookie（先解码真实 cookie，用 -H 头发送）
    function curlFormPost(url, formData, withCookie) {
        var dataArg = shellQuote(formData);
        function doPost(cookieHeader) {
            var cmd = 'curl -s -m 20' + (cookieHeader || '') +
                " -H 'Content-Type: application/x-www-form-urlencoded'" +
                " -H 'User-Agent: Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36'" +
                " -H 'X-Requested-With: XMLHttpRequest'" +
                " -H 'Referer: " + BASE + "/upload.php'" +
                ' --data ' + dataArg + ' ' + shellQuote(url);
            return exec(cmd, 30000).then(function (r) {
                var out = r.output.trim();
                var parsed = null;
                try { parsed = JSON.parse(out); } catch (e) {}
                return { raw: out, json: parsed };
            });
        }
        if (!withCookie) return doPost('');
        return loadCookie().then(function (cookie) {
            if (!cookie) {
                var err = new Error('未检测到 56.al 登录 Cookie。请先调用 tuoke_login_url 获取授权链接并完成登录，再调用 tuoke_set_cookie 粘贴 Cookie。');
                err.needLogin = true;
                throw err;
            }
            return doPost(' -H ' + shellQuote('Cookie: ' + cookie));
        });
    }

    // curl GET 带 cookie（先解码真实 cookie，用 -H 头发送）
    function curlGetWithCookie(url) {
        return loadCookie().then(function (cookie) {
            if (!cookie) {
                var err = new Error('未检测到 56.al 登录 Cookie。请先调用 tuoke_login_url 获取授权链接并完成登录，再调用 tuoke_set_cookie 粘贴 Cookie。');
                err.needLogin = true;
                throw err;
            }
            var cmd = 'curl -s -m 20 -H ' + shellQuote('Cookie: ' + cookie) +
                " -H 'User-Agent: Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36'" +
                " -H 'Referer: " + BASE + "/upload.php'" +
                ' ' + shellQuote(url);
            return exec(cmd, 30000).then(function (r) {
                return r.output;
            });
        });
    }

    // 带 Cookie 的 GET（Tools.Net 无 form 需求时可用；这里统一用 curl 保证 cookie 生效）
    function authedGet(url) {
        return loadCookie().then(function (cookie) {
            if (!cookie) {
                var err = new Error('未检测到 56.al 登录 Cookie。请先调用 tuoke_login_url 获取授权链接并完成登录，再调用 tuoke_set_cookie 粘贴 Cookie。');
                err.needLogin = true;
                throw err;
            }
            return curlGetWithCookie(url).then(function (html) {
                return { text: html, content: html, body: html, statusCode: 200 };
            });
        });
    }

    // 带 Cookie 的 form POST
    function authedFormPost(url, formData) {
        return loadCookie().then(function (cookie) {
            if (!cookie) {
                var err = new Error('未检测到 56.al 登录 Cookie。请先调用 tuoke_login_url 获取授权链接并完成登录，再调用 tuoke_set_cookie 粘贴 Cookie。');
                err.needLogin = true;
                throw err;
            }
            return curlFormPost(url, formData, true).then(function (res) {
                if (!res.json) throw new Error('接口返回非 JSON: ' + res.raw.substring(0, 200));
                return res.json;
            });
        });
    }

    // 无 cookie 的 form POST（登录引导用）
    function plainFormPost(url, formData) {
        return curlFormPost(url, formData, false).then(function (res) {
            if (!res.json) throw new Error('接口返回非 JSON: ' + res.raw.substring(0, 200));
            return res.json;
        });
    }

    function fetchCsrf() {
        return authedGet(BASE + '/upload.php').then(function (resp) {
            var html = respText(resp);
            var m = html.match(/id="csrf_token"\s+value="([a-f0-9]{32})"/i) ||
                    html.match(/name="csrf_token"\s+value="([a-f0-9]{32})"/i) ||
                    html.match(/value="([a-f0-9]{32})"[^>]*id="csrf_token"/i);
            if (!m) throw new Error('无法从上传页解析 csrf_token（Cookie 可能已失效或页面结构变化）');
            return m[1];
        });
    }

    function preUpload(csrf, name, md5, size, extra) {
        extra = extra || {};
        var body = 'csrf_token=' + encodeURIComponent(csrf) +
            '&name=' + encodeURIComponent(name) +
            '&hash=' + md5 +
            '&size=' + size +
            // show=1 与官方 uploadnew.js 一致（this.input.show 默认 true → '1'）。
            // 关键修正（v15.1）：官方秒传命中逻辑对 show=1 才会正常走 uploadSuccess 建任务/跳转；
            // 用 show=0 会导致已入库文件 pre_upload 返回 code:1「已存在」后不再创建脱壳任务，
            // complete 也报 CSRF TOKEN ERROR，形成孤儿记录（文件在库、任务缺失、官方无法重建）。
            // v15.1 统一改用 show=1，与官方行为严格对齐。
            '&show=1&ispwd=' + (extra.ispwd ? '1' : '0') + '&pwd=' + encodeURIComponent(extra.pwd || '');
        return authedFormPost(BASE + '/ajax.php?act=pre_upload', body).then(function (data) {
            if (data.code === 1) return { instant: true, hash: data.hash };
            if (data.code === 403) throw new Error('登录态无效（pre_upload 返回 403）。请重新执行 tuoke_login_url + tuoke_set_cookie 登录。');
            if (data.code !== 0) throw new Error('pre_upload 失败: ' + JSON.stringify(data));
            return { instant: false, hash: data.hash, chunksize: data.chunksize, chunks: data.chunks, received: data.received || [] };
        });
    }
    // v9.1: 孤儿任务重建（实测 2026-09-30 黄果短剧案例）。
    // 现象：分片全部上传完成后，若 complete_upload 因 csrf 一次性/网络中断失败，
    // 文件已入库（pre_upload code:1 exists:1）但任务表无任务（api_task exists:false）。
    // 此时官方网页 JS 对 code:1 直接跳转 file.php，不会再建任务；
    // ispwd=1&pwd=dump 兜底（v8）在当前服务端也已失效（实测同样返回 code:1 不建任务）。
    // 实测有效方案：补传一个分片（upload_part，哪怕服务端已有该分片）+ complete_upload（新 csrf），
    // 可触发服务端重新创建脱壳任务（黄果短剧案例即由此救回）。
    function checkTaskExists(hash) {
        // 用 curl 带 cookie 查询任务（api_task 无需登录，但保持 cookie 一致性）
        return loadCookie().then(function (cookie) {
            var cmd = 'curl -s -m 20 -H ' + shellQuote('Cookie: ' + cookie) +
                ' ' + shellQuote(BASE + '/api_task.php?hash=' + encodeURIComponent(hash) + '&since_id=0');
            return exec(cmd, 30000).then(function (r) {
                var data = null;
                try { data = JSON.parse(r.output.trim()); } catch (e) {}
                if (data && data.exists) return { taskExists: true, status: data.status || '' };
                return { taskExists: false, status: (data && data.status) || 'not_found' };
            }, function () { return { taskExists: false, status: 'query_error' }; });
        });
    }
    // ========== v15.3 核心修复 ==========
    // 【根因】官方 uploadnew.js 分片上传完成后，通过 uploadSuccess(hash) 跳转到 file.php?hash=<hash>，
    //        而【访问 file.php 这个页面本身会触发服务端创建/激活脱壳任务】。
    //        实测（2026-10-02 心养_1.0.0.apk）：
    //           - 上传完 5 个分片后，api_task 仍 not_found（任务未建）
    //           - 访问一次 file.php?hash= 后，api_task 立即变为 processing（任务开始接收、排队、执行）
    //        工具此前只调 checkTaskExists（api_task）而从未访问 file.php，导致分片传完但任务未触发，
    //        被误判为"孤儿"（文件在库、任务 not_found），实际只是漏了 file.php 这一步触发动作。
    // 【修复】新增 triggerTask(hash)：分片上传完成后（及秒传命中但任务 not_found 时），
    //        访问一次 file.php?hash= 触发服务端建任务，再重新查任务确认。
    function triggerTask(hash) {
        return authedGet(BASE + '/file.php?hash=' + encodeURIComponent(hash)).then(function () {
            // file.php 是页面访问（非 JSON），触发建任务后稍作等待再复查
            return new Promise(function (resolve) {
                setTimeout(function () { resolve(checkTaskExists(hash)); }, 1500);
            });
        }).catch(function () {
            // 访问 file.php 失败不致命，仍查一次任务兜底
            return checkTaskExists(hash);
        });
    }
    // 综合判定：先查任务，not_found 时尝试触发（访问 file.php）后再查一次。
    // 返回 { taskExists, status, triggered }，triggered 表示是否执行过 file.php 触发。
    function ensureTaskExists(hash) {
        return checkTaskExists(hash).then(function (chk) {
            if (chk.taskExists) return { taskExists: true, status: chk.status, triggered: false };
            return triggerTask(hash).then(function (chk2) {
                return { taskExists: chk2.taskExists, status: chk2.status, triggered: true };
            });
        });
    }
    // 上传一个真实分片（从本地文件读取指定分片，base64 编码后复用 uploadPart 通道）
    // 用于孤儿任务重建：文件已在库，服务端已有全部或部分分片，重传 chunk 1 也能通过校验。
    function uploadChunkFromFile(linuxPath, md5, chunkIndex, chunkSize) {
        var offset = (chunkIndex - 1) * chunkSize;
        var cmd = 'dd if=' + shellQuote(linuxPath) + ' bs=' + chunkSize + ' skip=' + (chunkIndex - 1) + ' count=1 2>/dev/null | base64 -w0';
        return exec(cmd, 60000).then(function (r) {
            var b64 = r.output.trim();
            if (!b64) throw new Error('读取分片 ' + chunkIndex + ' 失败');
            return fetchCsrf().then(function (csrf) {
                return uploadPart(csrf, md5, chunkIndex, b64);
            });
        });
    }
    function rebuildOrphanTask(name, md5, size, linuxPath, chunkSize) {
        // 先尝试直接补传 chunk 1 + complete（无需本地分片文件时也可用）
        return fetchCsrf().then(function (csrf) {
            // 分片 1 通常已入库；用极小内容不可行（服务端校验大小），必须传真实分片。
            // 优先从本地 APK 文件读取 chunk 1；若失败则用 uploadPart 的 b64 通道传文件头 8KB（仅探测）。
            return uploadChunkFromFile(linuxPath, md5, 1, chunkSize)
                .then(function () {
                    return fetchCsrf().then(function (csrf2) {
                        return completeUploadSafe(csrf2, md5);
                    }).then(function (cc) {
                        return checkTaskExists(md5).then(function (chk) {
                            return {
                                rebuilt: chk.taskExists,
                                taskExists: chk.taskExists,
                                status: chk.status,
                                uploadPart: 'ok',
                                completeWarning: cc.warning || null
                            };
                        });
                    });
                })
                .catch(function (err) {
                    // 补传失败也查一次任务（可能已建成）
                    return checkTaskExists(md5).then(function (chk) {
                        return {
                            rebuilt: chk.taskExists,
                            taskExists: chk.taskExists,
                            status: chk.status,
                            uploadPartError: String(err && err.message || err)
                        };
                    });
                });
        });
    }

    // upload_part 是 multipart 文件上传（$_FILES 接收，字段名 file）。
    // 实测 56.al 协议（uploadnew.js v1532）：
    //   1. file/hash/chunk/csrf_token 全部放 form 字段（不能用 URL query，否则 hash error；
    //      也不能 --data-binary 裸字节，否则"请选择文件"）。
    //   2. 关键：官方在一次完整上传会话中，csrf_token 在页面加载时抓取一次后【全程复用】，
    //      pre_upload → 各分片 upload_part → complete_upload 全部携带同一个 csrf。
    //      —— v14 的错误正是"每个分片前重抓 csrf + complete 前再重抓"，导致上传会话被搅乱，
    //         complete 时服务端找不到匹配 pre_upload 的会话 → 必然「参数校验失败」→ 任务未建 → poll 空转超时。
    // v15：本函数严格使用【调用方传入的会话 csrf】，绝不内部重抓。
    function uploadPart(csrf, md5, chunkIndex, chunkB64) {
        // 将 base64 解码为二进制文件，再 curl -F 以 multipart 上传
        var tmpFile = '/sdcard/Download/Operit/tuoke_out/_chunk_' + md5 + '_' + chunkIndex + '.bin';
        var b64File = tmpFile + '.b64';
        return exec('printf %s ' + shellQuote(chunkB64) + ' > ' + shellQuote(b64File) +
            ' && base64 -d ' + shellQuote(b64File) + ' > ' + shellQuote(tmpFile) +
            ' && rm -f ' + shellQuote(b64File), 30000)
            .then(function () {
                return loadCookie().then(function (cookie) {
                    if (!cookie) {
                        var err = new Error('未检测到 56.al 登录 Cookie。请先登录。');
                        err.needLogin = true;
                        throw err;
                    }
                    function doUpload(csrfToken) {
                        var cmd = 'curl -s -m 60 -H ' + shellQuote('Cookie: ' + cookie) +
                            " -H 'User-Agent: Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36'" +
                            " -H 'Referer: " + BASE + "/upload.php'" +
                            ' -F ' + shellQuote('file=@' + tmpFile + ';type=application/octet-stream') +
                            ' -F ' + shellQuote('hash=' + md5) +
                            ' -F ' + shellQuote('chunk=' + chunkIndex) +
                            ' -F ' + shellQuote('csrf_token=' + csrfToken) + ' ' +
                            shellQuote(BASE + '/ajax.php?act=upload_part');
                        return exec(cmd, 70000).then(function (r) {
                            var out = (r.output || '').trim();
                            var parsed = null;
                            try { parsed = JSON.parse(out); } catch (e) {}
                            if (parsed && parsed.code === 1) return { done: true };
                            if (parsed && parsed.code === 0) return { done: false };
                            if (parsed && parsed.code === 403) {
                                var err2 = new Error('登录态无效（upload_part 403）。请重新登录。');
                                err2.needLogin = true;
                                throw err2;
                            }
                            var msg = (parsed && parsed.msg) ? parsed.msg : out;
                            // v15：如实抛出错误，不做"参数校验失败→重抓csrf重试"的假设。
                            // （"参数校验失败"在孤儿状态/会话错乱下会无限重试，属误导；统一交给上层判定。）
                            if (parsed && parsed.msg) throw new Error('分片 ' + chunkIndex + ' 上传失败: ' + parsed.msg + '（' + out.substring(0, 120) + '）');
                            throw new Error('分片 ' + chunkIndex + ' 上传失败: ' + out.substring(0, 200));
                        });
                    }
                    return doUpload(csrf);
                });
            });
    }

    function b64ToArrayBuffer(b64) {
        var bin = atob(b64);
        var len = bin.length;
        var bytes = new Uint8Array(len);
        for (var i = 0; i < len; i++) bytes[i] = bin.charCodeAt(i);
        return bytes.buffer;
    }

    function md5OfBase64(b64) {
        var buf = b64ToArrayBuffer(b64);
        var words = new Uint32Array(buf.byteLength / 4);
        var dv = new DataView(buf);
        for (var i = 0; i < words.length; i++) words[i] = dv.getUint32(i * 4, false);
        return CryptoJS.MD5({ words: Array.prototype.slice.call(words), sigBytes: buf.byteLength }).toString();
    }

    function linuxMd5(linuxPath) {
        return exec('md5sum ' + shellQuote(linuxPath) + ' | awk \'{print $1}\'', 120000)
            .then(function (r) { return r.output.trim(); });
    }

    function completeUpload(csrf, md5) {
        var body = 'hash=' + md5 + '&csrf_token=' + encodeURIComponent(csrf);
        return authedFormPost(BASE + '/ajax.php?act=complete_upload', body).then(function (data) {
            if (data.code === 403) throw new Error('登录态无效（complete_upload 返回 403）。请重新登录。');
            if (data.code !== 0 && data.code !== 1) throw new Error('complete_upload 失败: ' + JSON.stringify(data));
            return data;
        });
    }
    // complete_upload 的容错包装：即使返回错误（CSRF/参数校验），任务也可能已在服务端创建，
    // 因此只记录警告不中断流程，后续通过 tuoke_status 查询实际任务状态。
    function completeUploadSafe(csrf, md5) {
        return completeUpload(csrf, md5).catch(function (err) {
            return { code: -1, warning: String(err && err.message || err) };
        });
    }
    // ========== 工具0: tuoke_browser_login（内置浏览器自动登录） ==========
    function tuoke_browser_login(params) {
        var openLogin = !params || params.open_login_page !== false;
        // 1. 打开 56.al 登录页（让用户在浏览器里完成登录）
        var navPromise = openLogin
            ? Tools.Net.browserNavigate(BASE + '/login.php')
            : Promise.resolve('skip');
        return navPromise.then(function () {
            // 2. 等用户登录（最多等 120 秒），轮询读取 cookie
            var deadline = Date.now() + 120000;
            function poll() {
                return Tools.Net.browserEvaluate({ function: '() => document.cookie' })
                    .then(function (ev) {
                        var text = String(ev || '');
                        // browserEvaluate 返回的内容里包含 Result 行
                        var m = text.match(/### Result\n([\s\S]*?)(?:\n\n###|\n$|$)/);
                        var cookieStr = m ? m[1].trim() : text.trim();
                        if (!cookieStr || cookieStr.indexOf('PHPSESSID') < 0) {
                            if (Date.now() > deadline) {
                                throw new Error('等待超时：未在浏览器中检测到 56.al 登录 Cookie。请先在打开的浏览器页面完成登录后重试，或使用 tuoke_set_cookie 手动粘贴。');
                            }
                            return new Promise(function (resolve) {
                                setTimeout(function () { resolve(poll()); }, 5000);
                            });
                        }
                        return cookieStr;
                    });
            }
            return poll();
        }).then(function (cookieStr) {
            // 3. 提取 PHPSESSID 和完整 cookie，保存
            var m = cookieStr.match(/PHPSESSID=[^;\s]+/i);
            if (!m) throw new Error('浏览器 Cookie 中未找到 PHPSESSID：' + cookieStr.substring(0, 120));
            return saveCookie(cookieStr).then(function () {
                // 4. 验证登录态
                var sess = extractPhpSessId(cookieStr);
                return authedGet(BASE + '/upload.php').then(function (resp) {
                    var html = respText(resp);
                    var cm = html.match(/id="csrf_token"\s+value="([a-f0-9]{32})"/i) ||
                             html.match(/name="csrf_token"\s+value="([a-f0-9]{32})"/i);
                    if (!cm) {
                        return { saved: true, valid: false, phpsessid: sess ? sess.substring(0, 6) + '...' : null, hint: 'Cookie 已从浏览器保存，但上传页无 csrf_token，登录态可能无效。' };
                    }
                    var body = 'csrf_token=' + cm[1] + '&name=verify.apk&hash=' + '0'.repeat(32) + '&size=1&show=1&ispwd=0&pwd=';
                    return authedFormPost(BASE + '/ajax.php?act=pre_upload', body).then(function (parsed) {
                        if (parsed && parsed.code === 403) {
                            return { saved: true, valid: false, phpsessid: sess ? sess.substring(0, 6) + '...' : null, preUpload: parsed, hint: '浏览器 Cookie 已保存，但登录态无效（403）。请确认浏览器中已成功登录 56.al 后重试。' };
                        }
                        return { saved: true, valid: true, phpsessid: sess ? sess.substring(0, 6) + '...' : null, preUpload: parsed, hint: '登录成功！Cookie 已从浏览器自动保存，可直接使用上传功能。' };
                    });
                });
            });
        });
    }

    // ========== 工具0: tuoke_login_url ==========
    function tuoke_login_url(params) {
        var provider = params.provider || 'github';
        var valid = { github: 1, qq: 1, gitee: 1, microsoft: 1, wx: 1 };
        if (!valid[provider]) throw new Error('不支持的登录方式: ' + provider + '（可选: github/qq/gitee/microsoft/wx）');
        return plainFormPost(BASE + '/login.php?act=connect', 'type=' + encodeURIComponent(provider) + '&app=0').then(function (data) {
            if (data.code !== 0 || !data.url) throw new Error('获取授权链接失败: ' + JSON.stringify(data));
            return {
                provider: provider,
                auth_url: data.url,
                steps: [
                    '1. 用浏览器打开上面的授权链接',
                    '2. 完成第三方账号登录/授权（页面会跳转到 56.al 并自动登录）',
                    '3. 登录成功后，从浏览器复制 Cookie（F12 → Network → 任意 56.al 请求 → Request Headers → Cookie）',
                    '4. 调用 tuoke_set_cookie 粘贴 Cookie 完成包内登录（只需一次，之后自动复用）'
                ],
                tip: 'Cookie 形如 PHPSESSID=xxxxxx；请妥善保管，不要分享给他人。'
            };
        });
    }
    // ========== 工具0b: tuoke_set_cookie ==========
    function tuoke_set_cookie(params) {
        var cookie = params.cookie;
        if (!cookie || !/PHPSESSID/i.test(cookie)) {
            throw new Error('Cookie 无效：未找到 PHPSESSID。请粘贴浏览器里的完整 Cookie 字符串（形如 PHPSESSID=xxxx; 其他=yyy）。');
        }
        return saveCookie(cookie).then(function () {
            return loadCookie().then(function (saved) {
                return authedGet(BASE + '/upload.php').then(function (resp) {
                    var html = respText(resp);
                    var m = html.match(/id="csrf_token"\s+value="([a-f0-9]{32})"/i) ||
                            html.match(/name="csrf_token"\s+value="([a-f0-9]{32})"/i);
                    if (!m) throw new Error('Cookie 已保存，但无法从上传页解析 csrf_token，请确认 Cookie 有效。');
                    var csrf = m[1];
                    var body = 'csrf_token=' + csrf + '&name=verify.apk&hash=' + '0'.repeat(32) + '&size=1&show=1&ispwd=0&pwd=';
                    return authedFormPost(BASE + '/ajax.php?act=pre_upload', body).then(function (parsed) {
                        var sess = extractPhpSessId(cookie);
                        if (parsed && parsed.code === 403) {
                            return { saved: true, valid: false, phpsessid: sess ? sess.substring(0, 6) + '...' : null, preUpload: parsed, hint: '登录态无效（403）。Cookie 可能已过期，请重新 tuoke_login_url 登录。' };
                        }
                        return { saved: true, valid: true, phpsessid: sess ? sess.substring(0, 6) + '...' : null, preUpload: parsed, hint: '登录成功，Cookie 已保存并持久化。' };
                    });
                });
            });
        });
    }

    // ========== 工具0c: tuoke_get_cookie ==========
    function tuoke_get_cookie() {
        return loadCookie().then(function (cookie) {
            var embedded = (cookie === EMBEDDED_COOKIE);
            if (!cookie) {
                return { saved: false, hint: '尚未保存 Cookie。请先 tuoke_login_url 获取授权链接并登录，再 tuoke_set_cookie 粘贴。' };
            }
            var sess = extractPhpSessId(cookie);
            var summary = {
                saved: true,
                embedded: embedded,
                phpsessid: sess ? sess.substring(0, 6) + '...' : null,
                keys: cookie.split(';').map(function (s) { return s.trim().split('=')[0]; }).filter(Boolean),
                cookieFile: COOKIE_FILE,
                hint: embedded ? '使用包内嵌 Cookie（开箱即用）。' : '使用已保存的 Cookie 文件。'
            };
            return authedGet(BASE + '/upload.php').then(function (resp) {
                var html = respText(resp);
                var m = html.match(/id="csrf_token"\s+value="([a-f0-9]{32})"/i) ||
                        html.match(/name="csrf_token"\s+value="([a-f0-9]{32})"/i);
                if (!m) {
                    summary.valid = false;
                    summary.hint = 'Cookie 已存在，但无法解析上传页 csrf_token，可能已失效。';
                    return summary;
                }
                var csrf = m[1];
                var body = 'csrf_token=' + csrf + '&name=verify.apk&hash=' + '0'.repeat(32) + '&size=1&show=1&ispwd=0&pwd=';
                return authedFormPost(BASE + '/ajax.php?act=pre_upload', body).then(function (parsed) {
                    summary.preUpload = parsed;
                    if (parsed && parsed.code === 403) {
                        summary.valid = false;
                        summary.hint = '登录态无效（403）。请重新 tuoke_login_url + tuoke_set_cookie。';
                    } else {
                        summary.valid = true;
                        summary.hint = '登录态有效，可直接使用上传功能。';
                    }
                    return summary;
                });
            });
        });
    }

    // ========== 工具0d: tuoke_clear_cookie ==========
    function tuoke_clear_cookie() {
        return clearCookie().then(function () {
            return { cleared: true, hint: '已清除 56.al 登录 Cookie。' };
        });
    }
    // ========== 工具1: tuoke_upload ==========
    function tuoke_upload(params) {
        var apkPath = params.apk_path;
        if (!apkPath) throw new Error('缺少 apk_path');
        return Tools.Files.readBinary(apkPath).then(function (fileResult) {
            var b64 = fileResult.contentBase64 || fileResult.base64 || (fileResult.data && fileResult.data.base64) || '';
            if (!b64) throw new Error('readBinary 返回空: ' + apkPath);
            var size = fileResult.size || Math.floor(b64.length * 3 / 4);
            if (size > CHUNK_SIZE) {
                throw new Error('文件大小 ' + size + ' 超过单块上限，请使用 tuoke_upload_big 或网页版。');
            }
            var md5 = md5OfBase64(b64);
            var name = apkPath.split('/').pop();
            var csrfPromise = params.csrf_token ? Promise.resolve(params.csrf_token) : fetchCsrf();
            return csrfPromise.then(function (csrf) {
                // v15：一次会话只抓一次 csrf，pre_upload + upload_part + complete_upload 全程复用同一 csrf，
                // 严格对齐官方 uploadnew.js 会话模型。绝不在 complete 前重抓（重抓会破坏会话匹配导致参数校验失败）。
                return preUpload(csrf, name, md5, size).then(function (pre) {
                    if (pre.instant) {
                        // v15：官方协议 code:1（秒传命中）直接 uploadSuccess，不再调用 complete_upload。
                        // v15.3：命中后任务可能未建，ensureTaskExists 会在 not_found 时访问 file.php 触发。
                        return ensureTaskExists(pre.hash).then(function (chk) {
                            if (chk.taskExists) return { hash: pre.hash, instant: true, name: name, size: size, md5: md5, taskExists: true, status: chk.status, triggered: chk.triggered };
                            return {
                                hash: pre.hash, instant: true, name: name, size: size, md5: md5,
                                taskExists: false, status: chk.status, orphan: true,
                                hint: '访问 file.php 触发后任务仍不存在，文件可能无法建脱壳任务。'
                            };
                        });
                    }
                    return uploadPart(csrf, md5, 1, b64).then(function (res) {
                        // v15.2：单分片时 upload_part 返回 code:1 即代表服务端已自动完成上传（同大文件最后一片逻辑）。
                        // 此时绝不能再调 complete_upload，否则 CSRF TOKEN ERROR → 孤儿。
                        // v15.3：ensureTaskExists 会在 not_found 时访问 file.php 触发建任务后复查。
                        if (res && res.done) {
                            return ensureTaskExists(md5).then(function (chk) {
                                return {
                                    hash: pre.hash, instant: false, name: name, size: size, md5: md5,
                                    completed: true, completeCode: 1, autoCompleteByServer: true,
                                    taskExists: chk.taskExists, status: chk.status, triggered: chk.triggered
                                };
                            });
                        }
                        // 防御性：单分片未返回 done（理论上不会走到），复用会话 csrf 调 complete
                        return completeUpload(csrf, md5).then(function (cc) {
                            return { hash: pre.hash, instant: false, name: name, size: size, md5: md5, completed: true, completeCode: cc.code };
                        });
                    });
                });
            });
        });
    }

    // ========== 工具1b: tuoke_upload_big（大文件） ==========
    function tuoke_upload_big(params) {
        var apkPath = params.apk_path;
        if (!apkPath) throw new Error('缺少 apk_path');
        var linuxPath = toLinuxPath(apkPath);
        var name = apkPath.split('/').pop();
        return exec('stat -c %s ' + shellQuote(linuxPath), 15000).then(function (st) {
            var size = parseInt(st.output.trim(), 10);
            if (!size) throw new Error('无法获取文件大小: ' + apkPath);
            return linuxMd5(linuxPath).then(function (md5) {
                var csrfPromise = params.csrf_token ? Promise.resolve(params.csrf_token) : fetchCsrf();
                return csrfPromise.then(function (csrf) {
                    // v15：一次会话只抓一次 csrf，pre_upload + 全部分片 + complete_upload 全程复用。
                    return preUpload(csrf, name, md5, size).then(function (pre) {
                        if (pre.instant) {
                            // v15：官方 code:1 秒传命中直接成功，不再 complete。
                            // v15.3：命中后任务可能尚未创建，先查任务，not_found 时访问 file.php 触发建任务。
                            return ensureTaskExists(pre.hash).then(function (chk) {
                                if (chk.taskExists) return { hash: pre.hash, instant: true, name: name, size: size, md5: md5, taskExists: true, status: chk.status, triggered: chk.triggered };
                                return {
                                    hash: pre.hash, instant: true, name: name, size: size, md5: md5,
                                    taskExists: false, status: chk.status, orphan: true,
                                    hint: '访问 file.php 触发后任务仍不存在，文件可能无法建脱壳任务。'
                                };
                            });
                        }
                        var chunkSize = pre.chunksize || CHUNK_SIZE;
                        // v15.2：分片循环把"最后一片是否已由服务端自动完成"通过 allDone 传回。
                        // 实测（2026-10-02）：56.al 的 upload_part 在【最后一片】上传时即返回 code:1「文件上传成功」，
                        // 服务端在收齐最后一片时已自动完成上传（自动 complete），此时【绝不能再调 complete_upload】，
                        // 否则必然报 CSRF TOKEN ERROR（complete 对象已失效），导致"文件在库、任务未建"的孤儿。
                        return uploadChunksViaLinux(csrf, md5, name, linuxPath, size, chunkSize, pre.received || [])
                            .then(function (res) {
                                var doneByServer = !!(res && res.allDone);
                                if (doneByServer) {
                                    // 最后一片已触发服务端自动完成，跳过 complete_upload。
                                    // v15.3：服务端上传完分片只建"文件记录"，【必须访问 file.php 才触发建脱壳任务】。
                                    //        ensureTaskExists 会先查任务，not_found 时自动访问 file.php 触发后复查。
                                    return ensureTaskExists(md5).then(function (chk) {
                                        return {
                                            hash: pre.hash, instant: false, name: name, size: size, md5: md5,
                                            completed: true, completeCode: 1, autoCompleteByServer: true,
                                            taskExists: chk.taskExists, status: chk.status, triggered: chk.triggered
                                        };
                                    });
                                }
                                // 分片未全部触发自动完成（理论上不会走到，防御性保留），复用会话 csrf 调 complete
                                return completeUpload(csrf, md5).then(function (cc) {
                                    return { hash: pre.hash, instant: false, name: name, size: size, md5: md5, completed: true, completeCode: cc.code };
                                });
                            });
                    });
                });
            });
        });
    }

    // 大文件分片上传：python3 读偏移输出 base64，JS 一次只持有一片
    function uploadChunksViaLinux(csrf, md5, name, linuxPath, size, chunkSize, received) {
        var totalChunks = Math.ceil(size / chunkSize);
        var receivedSet = {};
        (received || []).forEach(function (i) { receivedSet[i] = true; });

        function readChunkB64(index) {
            var offset = index * chunkSize;
            var len = Math.min(chunkSize, size - offset);
            var py = "import sys,base64;f=open(sys.argv[1],'rb');f.seek(int(sys.argv[2]));d=f.read(int(sys.argv[3]));sys.stdout.write(base64.b64encode(d).decode())";
            return exec('python3 -c ' + shellQuote(py) + ' ' + shellQuote(linuxPath) + ' ' + offset + ' ' + len, 60000)
                .then(function (r) { return r.output.trim(); });
        }

        var idx = 0;
        var allDone = false;
        function next() {
            if (idx >= totalChunks || allDone) return Promise.resolve();
            var cur = idx;
            idx++;
            if (receivedSet[cur]) return next();
            return uploadChunkWithRetry(cur).then(function (res) {
                if (res && res.done) allDone = true; // 最后一片已触发任务创建
                return next();
            });
        }
        // 单分片上传：失败自动重试（最多 3 次），并利用服务端 received 列表做断点续传
        function uploadChunkWithRetry(cur) {
            var attempts = 0;
            function attempt() {
                attempts++;
                return readChunkB64(cur).then(function (b64) {
                    return uploadPart(csrf, md5, cur + 1, b64).then(function (res) {
                        return res;
                    }, function (err) {
                        if (attempts >= 3) throw err; // 重试耗尽
                        return new Promise(function (resolve) {
                            setTimeout(function () {
                                // 重试前先向服务端确认已收分片（断点续传）
                                resolve(preUpload(csrf, name, md5, size).then(function (pre) {
                                    if (pre.instant) return { done: true }; // 服务端已有完整文件
                                    var recv = pre.received || [];
                                    recv.forEach(function (i) { receivedSet[i - 1] = true; });
                                    if (receivedSet[cur]) return { done: false }; // 该片服务端已收到，跳过
                                    return attempt();
                                }));
                            }, 1500 * attempts);
                        });
                    });
                });
            }
            return attempt();
        }
        return next().then(function () { return { allDone: allDone }; });
    }
    // ========== 工具2: tuoke_status ==========
    function tuoke_status(params) {
        var hash = params.hash;
        var sinceId = params.since_id || 0;
        if (!hash) throw new Error('缺少 hash');
        return Tools.Net.httpGet(BASE + '/api_task.php?hash=' + encodeURIComponent(hash) + '&since_id=' + sinceId)
            .then(function (resp) {
                var data = JSON.parse(respText(resp));
                if (!data.exists) throw new Error(data.msg || '任务不存在');
                return {
                    hash: hash,
                    status: data.status,
                    exists: true,
                    logs: (data.logs || []).map(function (l) {
                        return { id: l.id, time: l.time, content: l.content };
                    }),
                    filetime: data.filetime || 0
                };
            });
    }

    // ========== 工具3: tuoke_download（Linux 流式下载 + 7z 解压 + dex 修复） ==========
    function tuoke_download(params) {
        var hash = params.hash;
        var skipUnpack = params.skip_unpack === true;
        if (!hash) throw new Error('缺少 hash');
        var outDir = params.output_dir || (params.apk_path ? deriveOutDir(params.apk_path) : '/sdcard/Download/Operit/tuoke_out/' + hash);
        var linuxTmp = '/sdcard/Download/Operit/tuoke_out/_tmp_' + hash;
        var sevenPath = linuxTmp + '/' + hash + '.7z';

        return Tools.Net.httpGet(BASE + '/api_task.php?hash=' + encodeURIComponent(hash) + '&since_id=0')
            .then(function (resp) {
                var data = JSON.parse(respText(resp));
                if (!data.exists) throw new Error('任务不存在');
                if (data.status !== 'success') throw new Error('任务未完成，当前状态: ' + data.status);
            })
            .then(function () {
                return exec('mkdir -p ' + shellQuote(linuxTmp), 15000);
            })
            .then(function () {
                var dlUrl = BASE + '/api_download.php?url=' + encodeURIComponent(hash);
                // --http1.1：下载接口 302 到 OneDrive，HTTP/2 跟随重定向会失败（curl exit 92）
                // --retry-all-errors + --retry + -C -：网络瞬断（Recv failure/exit56）自动重试并断点续传
                return exec('curl -L --http1.1 --fail --retry 8 --retry-delay 3 --retry-all-errors -C - --max-time 300 -o ' + shellQuote(sevenPath) + ' ' + shellQuote(dlUrl), 660000);
            })
            .then(function () {
                // 用 stat 精确获取文件大小（不用 ls 正则，避免误解析）
                return exec('stat -c %s ' + shellQuote(sevenPath), 15000);
            })
            .then(function (statr) {
                var dlSize = parseInt(statr.output.trim(), 10) || 0;
                var note = '已下载 7z 到: ' + sevenPath + ' (大小 ' + dlSize + 'B)';
                if (skipUnpack) {
                    return { hash: hash, savedPath: sevenPath, size: dlSize, note: note + '（skip_unpack=true，未解压）' };
                }
                return unpack7z(linuxTmp, sevenPath).then(function (unpacked) {
                    return fixDexInDir(linuxTmp).then(function (dexFixed) {
                        // 产物落地：递归复制解压出的 dex / txt / 7z 到 outDir（默认目标 APK 同目录；dex 可能在子目录 dex_out/ 内）
                        var outDirSh = shellQuote(outDir);
                        return exec('mkdir -p ' + outDirSh, 15000).then(function () {
                            var copyCmd = 'cp -f ' + shellQuote(linuxTmp + '/' + hash + '.7z') + ' ' + outDirSh +
                                '; find ' + shellQuote(linuxTmp) + ' -name "*.dex" -exec cp -f {} ' + outDirSh + ' \\;' +
                                '; find ' + shellQuote(linuxTmp) + ' -maxdepth 2 -name "*.txt" -exec cp -f {} ' + outDirSh + ' \\;' +
                                '; true';
                            return exec(copyCmd, 30000).then(function () {
                                return exec('ls ' + outDirSh + ' | grep -E "(\\.dex|\\.txt|\\.7z)$" | grep -F "' + hash + '" || ls ' + outDirSh + ' | grep -E "(\\.dex|\\.txt|\\.7z)$"', 15000);
                            }).then(function (lsr) {
                                var files = lsr.output.split('\n').filter(function (s) { return s.trim(); });
                                // v9: 自动跑 dexlib2 规范化（等价 MT 管理器 dex 修复），输出到 outDir/修复dex/
                                var cleanOut = outDir + '/修复dex';
                                return exec('mkdir -p ' + shellQuote(cleanOut) + ' && find ' + shellQuote(linuxTmp) + ' -name "*.dex" -type f | sort', 30000)
                                    .then(function (fr) {
                                        var dexFiles = fr.output.split('\n').map(function (s) { return s.trim(); }).filter(function (s) { return s; });
                                        var pairs = dexFiles.map(function (f) {
                                            return [f, cleanOut + '/' + f.split('/').pop()];
                                        });
                                        return runDexClean(pairs).then(function (cleanRes) {
                                            return {
                                                hash: hash,
                                                savedPath: sevenPath,
                                                size: dlSize,
                                                unpackDir: linuxTmp,
                                                outputDir: outDir,
                                                unpacked: unpacked,
                                                dexFixed: dexFixed,
                                                outputFiles: files,
                                                dexClean: { outputDir: cleanOut, cleaned: cleanRes.length, files: cleanRes },
                                                note: '脱壳完成。产物已复制到: ' + outDir + '（dex/txt/7z，dex 头已修复）；dexlib2 规范化修复版（等价 MT dex 修复）在 ' + cleanOut + '。'
                                            };
                                        });
                                    });
                            });
                        });
                    });
                });
            });
    }

    // 7z 解压（密码 dump），返回文件列表；失败时输出真实错误
    // 先探测真实格式（56.al 的"7z"实际可能是 zip/rar），再按格式解压
    function unpack7z(dir, sevenPath) {
        // 56.al 产物实际结构（实测）：
        //   外层 = 真 7z（LZMA2 + 7zAES，密码 dump），内含 3 个 txt + 内层同名 .7z
        //   内层 = zip 变体（7-Zip 0.4，unzip 不认，7za 可识别），内含 classes.dex
        // 注意：/usr/bin/7z 的 l 命令在 proot 环境会 hang，必须用 7za 且加 timeout；
        //       内层归档与外层同名，必须先解压到 extract/ 子目录避免覆盖。
        var extractDir = dir + '/extract';
        return exec('mkdir -p ' + shellQuote(extractDir), 15000)
            .then(function () {
                // 解压外层（7za 自动识别 7z/zip 变体）
                return exec('cd ' + shellQuote(dir) + ' && timeout 240 /usr/bin/7za x -p' + PASSWORD + ' -y -oextract ' + shellQuote(sevenPath) + ' >/dev/null 2>&1; ec=$?; echo "7z_exit=$ec"; [ $ec -eq 0 ]', 300000);
            })
            .then(function () {
                // 递归解压内层归档（最多 3 层），7za 自动识别格式
                return exec('cd ' + shellQuote(dir) + ' && for layer in 1 2 3; do found=$(find extract -type f \\( -name "*.7z" -o -name "*.zip" \\) 2>/dev/null); [ -z "$found" ] && break; for f in $found; do d=$(dirname "$f"); timeout 240 /usr/bin/7za x -p' + PASSWORD + ' -y -o"$d" "$f" >/dev/null 2>&1; done; done; echo done', 600000);
            })
            .then(function (r) {
                return exec('find ' + shellQuote(dir) + ' -type f | sed \'s|^' + dir + '/||\'', 30000);
            })
            .then(function (r) {
                return r.output.split('\n').filter(function (s) { return s.trim(); });
            })
            .catch(function (e) {
                throw new Error('7z 解压失败: ' + ((e && e.output || e && e.message) || '').substring(0, 300));
            });
    }

    // 递归查找 dex 并修复头（python 流式）
    function fixDexInDir(dir) {
        var py = String.raw`
import sys, os, struct
def fix(path):
    sz = os.path.getsize(path)
    if sz < 112:
        return (path, 'too_small')
    with open(path, 'r+b') as f:
        head = f.read(112)
        if head[0:8] != b'dex\n035\0':
            return (path, 'not_dex_magic')
        if sz >= 0xFFFFFFFF:
            return (path, 'large_file')
        f.seek(0)
        f.write(b'dex\n035\0')
        f.seek(32)
        f.write(struct.pack('<I', sz))
        f.seek(36)
        f.write(struct.pack('<I', 112))
    return (path, 'fixed')
results = []
for root, _, files in os.walk(sys.argv[1]):
    for fn in files:
        if fn.endswith('.dex') or fn.endswith('.DEX'):
            p = os.path.join(root, fn)
            try:
                results.append(fix(p))
            except Exception as e:
                results.append((p, 'error:' + str(e)))
for p, st in results:
    print(p + '|' + st)
`;
        return exec('python3 -c ' + shellQuote(py) + ' ' + shellQuote(dir), 120000)
            .then(function (r) {
                return r.output.split('\n').filter(function (s) { return s.trim(); }).map(function (line) {
                    var i = line.lastIndexOf('|');
                    return { file: line.substring(0, i), status: line.substring(i + 1) };
                });
            });
    }
    // ========== 工具4: tuoke_all ==========
    function tuoke_all(params) {
        var apkPath = params.apk_path;
        var maxWait = params.max_wait_seconds || 1800;
        if (!apkPath) throw new Error('缺少 apk_path');
        var start = Date.now();
        return exec('stat -c %s ' + shellQuote(toLinuxPath(apkPath)), 15000)
            .then(function (st) {
                var size = parseInt(st.output.trim(), 10);
                var uploadFn = size > CHUNK_SIZE ? tuoke_upload_big : tuoke_upload;
                return uploadFn({ apk_path: apkPath }).then(function (uploadRes) {
                    var hash = uploadRes.hash;
                    var outDir = params.output_dir || deriveOutDir(apkPath) || dirname(apkPath);
                    // v15: 秒传命中(instant)且任务存在 -> 直接取历史结果。
                    // 孤儿（instant 且 taskExists=false）：官方协议 code:1 直接成功不再建任务，
                    // 本渠道无法重建（实测补传分片/新 csrf complete 均被服务端拒绝），如实中断并给换渠道指引。
                    if (uploadRes.instant && uploadRes.taskExists === false && uploadRes.orphan) {
                        return Promise.resolve({
                            hash: hash,
                            upload: uploadRes,
                            interrupted: true,
                            reason: "orphan_task",
                            retryable: false,
                            hint: uploadRes.hint || '文件已入库但脱壳任务不存在（孤儿记录）。官方 56.al 协议下无法通过上传渠道重建任务，请从云盘取回历史产物，或换用其他脱壳渠道/本地脱壳。',
                            summary: "云脱壳中断: 文件已入库但任务不存在（孤儿），本渠道无法重建"
                        });
                    }
                    function poll() {
                        return tuoke_status({ hash: hash }).then(function (s) {
                            if (s.status === 'success') return s;
                            if (s.status === 'error') throw new Error('任务异常: ' + JSON.stringify(s.logs.slice(-3)));
                            if (Date.now() - start > maxWait * 1000) throw new Error('等待超时(' + maxWait + 's)');
                            return new Promise(function (resolve) {
                                setTimeout(function () { resolve(poll()); }, 60000);
                            });
                        }, function (err) {
                            // 任务刚创建时查询可能瞬时不存在，容错重试；但连续不存在要留意孤儿状态
                            if (Date.now() - start > maxWait * 1000) {
                                var e2 = new Error('等待超时(' + maxWait + 's)，任务未建立。可能原因：complete 未成功创建任务（孤儿状态）。可手动查 ' + BASE + '/api_task.php?hash=' + hash + ' 确认。');
                                e2.orphanPossible = true;
                                throw e2;
                            }
                            return new Promise(function (resolve) {
                                setTimeout(function () { resolve(poll()); }, 60000);
                            });
                        });
                    }
                    return poll().then(function (finalSt) {
                        return tuoke_download({ hash: hash, output_dir: outDir, apk_path: apkPath }).then(function (dlRes) {
                            return {
                                hash: hash,
                                upload: uploadRes,
                                finalStatus: finalSt.status,
                                logs: finalSt.logs,
                                download: dlRes,
                                summary: '云脱壳完成: ' + apkPath + ' -> ' + dlRes.unpackDir + ' (解压密码: ' + PASSWORD + ')'
                            };
                        });
                    });
                });
            });
    }

    // ========== 工具5: tuoke_fix_dex ==========
    function tuoke_fix_dex(params) {
        var dexPath = params.dex_path;
        if (!dexPath) throw new Error('缺少 dex_path');
        var linuxPath = toLinuxPath(dexPath);
        var outPath = params.output_path ? toLinuxPath(params.output_path) : linuxPath;
        var py = String.raw`
import sys, os, struct
src = sys.argv[1]
dst = sys.argv[2]
sz = os.path.getsize(src)
if sz < 112:
    print('too_small'); sys.exit(1)
with open(src, 'rb') as f:
    head = f.read(112)
if head[0:8] != b'dex\n035\0':
    print('not_dex_magic'); sys.exit(1)
if src == dst:
    with open(dst, 'r+b') as f:
        f.seek(32); f.write(struct.pack('<I', sz))
        f.seek(36); f.write(struct.pack('<I', 112))
else:
    with open(src, 'rb') as fi, open(dst, 'wb') as fo:
        fo.write(fi.read())
    with open(dst, 'r+b') as f:
        f.seek(32); f.write(struct.pack('<I', sz))
        f.seek(36); f.write(struct.pack('<I', 112))
print('fixed:' + dst)
`;
        return exec('python3 -c ' + shellQuote(py) + ' ' + shellQuote(linuxPath) + ' ' + shellQuote(outPath), 120000)
            .then(function (r) {
                return { dexPath: outPath, result: r.output.trim() };
            });
    }

    // ========== 工具5b: tuoke_dex_clean（dexlib2 规范化重写 = MT 管理器 dex 修复） ==========
    var DEXCLEAN_DIR = '/sdcard/Download/Operit/dexclean';
    var DEXCLEAN_CP = 'dexlib2-2.5.2.jar:util-2.5.2.jar:guava-27.1-android.jar:jsr305-3.0.2.jar:.';
    // 对一组 dex 文件跑 DexClean（java 批量），返回 {in,out,ok,info} 列表
    function runDexClean(inOutPairs) {
        if (!inOutPairs.length) return Promise.resolve([]);
        var args = '30';
        inOutPairs.forEach(function (p) { args += ' ' + shellQuote(p[0]) + ' ' + shellQuote(p[1]); });
        return exec('cd ' + shellQuote(DEXCLEAN_DIR) + ' && java -Xmx1g -cp ' + shellQuote(DEXCLEAN_CP) + ' DexClean ' + args, 1200000)
            .then(function (r) {
                var lines = (r.output || '').split('\n').filter(function (s) { return s.trim(); });
                var results = [];
                lines.forEach(function (l) {
                    if (l.indexOf('OK classes=') !== 0) return;
                    var m = l.match(/classes=(\d+) in=(.+) out=(.+)/);
                    if (m) results.push({ classes: parseInt(m[1], 10), in: m[2], out: m[3], ok: true });
                });
                return results;
            }, function (err) {
                throw new Error('dexlib2 修复失败: ' + ((err && err.output || err && err.message) || '').substring(0, 300));
            });
    }
    function tuoke_dex_clean(params) {
        var dexPath = params.dex_path;
        if (!dexPath) throw new Error('缺少 dex_path');
        var linuxIn = toLinuxPath(dexPath);
        var outDir = params.output_dir ? toLinuxPath(params.output_dir) : null;
        return exec('if [ -d ' + shellQuote(linuxIn) + ' ]; then echo dir; else echo file; fi', 15000)
            .then(function (r) {
                var isDir = r.output.trim() === 'dir';
                var files = [];
                var base = linuxIn;
                if (isDir) {
                    if (!outDir) outDir = linuxIn.replace(/\/$/, '') + '/修复dex';
                } else {
                    var idx = linuxIn.lastIndexOf('/');
                    base = idx >= 0 ? linuxIn.substring(0, idx) : '.';
                    if (!outDir) outDir = base + '/修复dex';
                }
                return exec('mkdir -p ' + shellQuote(outDir) + ' && find ' + shellQuote(linuxIn) + ' -name "*.dex" -type f | sort', 30000)
                    .then(function (fr) {
                        fr.output.split('\n').forEach(function (s) {
                            var t = s.trim();
                            if (t) files.push(t);
                        });
                        if (!files.length) throw new Error('未找到 dex 文件: ' + dexPath);
                        var pairs = files.map(function (f) {
                            var name = f.split('/').pop();
                            return [f, outDir + '/' + name];
                        });
                        return runDexClean(pairs).then(function (results) {
                            return {
                                input: dexPath,
                                outputDir: outDir,
                                total: results.length,
                                cleaned: results.filter(function (x) { return x.ok; }).length,
                                files: results.map(function (x) { return { in: x.in, out: x.out, classes: x.classes }; }),
                                note: 'dexlib2 规范化完成（等价 MT dex 修复：签名/去重/紧凑重排）。输出目录: ' + outDir
                            };
                        });
                    });
            });
    }
    // ========== 工具6: tuoke_check_auth ==========
    function tuoke_check_auth() {
        return loadCookie().then(function (cookie) {
            if (!cookie) {
                return {
                    saved: false,
                    valid: false,
                    hint: '尚未保存 Cookie。请先 tuoke_login_url 获取授权链接并登录，再 tuoke_set_cookie 粘贴。',
                    loginGuide: 'tuoke_login_url(provider) → 浏览器授权 → 复制 Cookie → tuoke_set_cookie(cookie)'
                };
            }
            var sess = extractPhpSessId(cookie);
            var diag = {
                saved: true,
                phpsessid: sess ? sess.substring(0, 6) + '...' : null,
                cookieFile: COOKIE_FILE
            };
            return authedGet(BASE + '/upload.php').then(function (resp) {
                diag.pageStatus = resp.statusCode;
                var html = respText(resp);
                var m = html.match(/id="csrf_token"\s+value="([a-f0-9]{32})"/i) ||
                        html.match(/name="csrf_token"\s+value="([a-f0-9]{32})"/i);
                diag.pageHasCsrf = !!m;
                var csrf = m ? m[1] : '0';
                var body = 'csrf_token=' + csrf + '&name=verify.apk&hash=' + '0'.repeat(32) + '&size=1&show=1&ispwd=0&pwd=';
                return authedFormPost(BASE + '/ajax.php?act=pre_upload', body).then(function (parsed) {
                    diag.preUploadParsed = parsed;
                    if (parsed && parsed.code === 403) {
                        diag.valid = false;
                        diag.hint = '登录态无效（pre_upload 403）。Cookie 已过期/失效，请重新登录：tuoke_login_url → 浏览器授权 → tuoke_set_cookie。';
                    } else {
                        diag.valid = true;
                        diag.hint = '登录态有效，可直接使用上传功能。';
                    }
                    return diag;
                });
            });
        });
    }

    return {
        tuoke_browser_login: wrap(tuoke_browser_login),
        tuoke_login_url: wrap(tuoke_login_url),
        tuoke_set_cookie: wrap(tuoke_set_cookie),
        tuoke_get_cookie: wrap(tuoke_get_cookie),
        tuoke_clear_cookie: wrap(tuoke_clear_cookie),
        tuoke_upload: wrap(tuoke_upload),
        tuoke_upload_big: wrap(tuoke_upload_big),
        tuoke_status: wrap(tuoke_status),
        tuoke_download: wrap(tuoke_download),
        tuoke_all: wrap(tuoke_all),
        tuoke_fix_dex: wrap(tuoke_fix_dex),
        tuoke_check_auth: wrap(tuoke_check_auth),
        tuoke_dex_clean: wrap(tuoke_dex_clean)
    };
})();

exports.tuoke_browser_login = tuoke56.tuoke_browser_login;
exports.tuoke_login_url = tuoke56.tuoke_login_url;
exports.tuoke_set_cookie = tuoke56.tuoke_set_cookie;
exports.tuoke_get_cookie = tuoke56.tuoke_get_cookie;
exports.tuoke_clear_cookie = tuoke56.tuoke_clear_cookie;
exports.tuoke_upload = tuoke56.tuoke_upload;
exports.tuoke_upload_big = tuoke56.tuoke_upload_big;
exports.tuoke_status = tuoke56.tuoke_status;
exports.tuoke_download = tuoke56.tuoke_download;
exports.tuoke_all = tuoke56.tuoke_all;
exports.tuoke_fix_dex = tuoke56.tuoke_fix_dex;
exports.tuoke_check_auth = tuoke56.tuoke_check_auth;
exports.tuoke_dex_clean = tuoke56.tuoke_dex_clean;