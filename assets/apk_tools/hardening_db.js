/*
METADATA
{
"name": "加固特征库",
"display_name": { "zh": "加固特征库", "en": "Hardening DB" },
"description": { "zh": "Android APK加固壳特征识别数据库，内置49种加固壳的桩类/代理类/lib/assets特征与删壳处置路线。提供按桩类查、按特征文件查、综合判定三种工具。", "en": "Android packer signature database with 49 packers, query by stub/feature/combined." },
"enabledByDefault": true,
"category": "Reverse",
"tools": [
  { "name": "identify_by_stub", "description": { "zh": "输入桩类Application类名(Manifest的application android:name)，返回匹配壳名、特征so、特征assets与删壳处置路线。", "en": "Query packer by stub Application class name." }, "parameters": [ { "name": "stubClass", "description": { "zh": "桩类Application类名", "en": "Stub class" }, "type": "string", "required": true } ] },
  { "name": "identify_by_feature", "description": { "zh": "输入加固壳的特征文件路径/文件名，返回匹配壳名与处置要点。", "en": "Query packer by feature file." }, "parameters": [ { "name": "feature", "description": { "zh": "特征文件名或路径", "en": "Feature file" }, "type": "string", "required": true } ] },
  { "name": "identify_combined", "description": { "zh": "同时提供桩类/lib/assets特征，给出最佳壳型匹配与处置建议。", "en": "Combined packer detection." }, "parameters": [ { "name": "stubClass", "description": { "zh": "桩类Application类名(可空)", "en": "Stub class (optional)" }, "type": "string", "required": false }, { "name": "libs", "description": { "zh": "lib特征so列表,JSON数组字符串", "en": "List of feature .so (JSON array string)" }, "type": "string", "required": false }, { "name": "assets", "description": { "zh": "assets特征文件列表,JSON数组字符串", "en": "List of feature asset files (JSON array string)" }, "type": "string", "required": false } ] }
]
}
*/

const hardeningDB = (function () {
  // 特征数据从 data.js 加载
  const DB = [
  { name: "360加固", sample: true, stub: "com.stub.StubApp", stub2: "", lib: ["libjiagu.so", "libjiagu_a64.so", "libjiagu_x64.so", "libjiagu_x86.so"], assets: [".jgapp"], handler: "删除StubApp桩类 + libjiagu*.so + .jgapp；还原原Application" },
  { name: "360企业加固", sample: true, stub: "dohtemtupni.uruhsnix.moc.StubApp", stub2: "", lib: ["libjiagu_vip_a64.so", "libjiagu_vip_mips.a", "libjiagu_vip_x64.so", "libjgcxi_a64.so", "libjiagu.so", "libjiagu_a64.so", "libjiagu_x64.so", "libjiagu_x86.so"], assets: [".jgapp"], handler: "同360加固；桩类为倒序字符串，实际类名可能需倒序还原；删libjiagu*.so+.jgapp" },
  { name: "ARM加固", sample: true, stub: "arm.StubApp", stub2: "", lib: ["libArmEpicVm(高级).so", "libarm_protect(初级).so"], assets: ["config.so", "被加固的dex.dex"], handler: "删除arm.StubApp桩类 + ARM壳so" },
  { name: "Appdome加固", sample: true, stub: "android.support.v4.soft.ApplicationMain", stub2: "", lib: ["libloader.so"], assets: ["m7a", "m8a"], handler: "删除桩类 + libloader.so + m7a/m8a" },
  { name: "CTools加固(无样本)", sample: false, stub: "crash.stub.ProxyApplication", stub2: "", lib: ["libnmmp.so", "libnmmvm.so"], assets: ["ByCrash"], handler: "删除crash.stub包类 + libnmmp/libnmmvm" },
  { name: "DexProtect", sample: true, stub: "ProtectedTvPlayerApplication", stub2: "ProtectedAppComponentFactory", lib: [], assets: ["classes.dex.dat", "dp.arm-v7.so.dat", "dp.arm-v8.so.dat", "dp.mp3", "dp.x86.so.dat", "dp.x86_64.so.dat", "ic.dat", "resources.dat", "se.dat"], handler: "删除桩类ProtectedTvPlayerApplication + appComponentFactory(ProtectedAppComponentFactory) + dp.*.dat等壳数据；结果可能不准确" },
  { name: "Epic v2", sample: true, stub: "Epic.ProtectApp", stub2: "", lib: [], assets: ["Epic_dexs/", "Epic_so/", "app_name"], handler: "删除Epic包 + Epic_dexs/Epic_so/app_name" },
  { name: "Frezrik加固(无样本)", sample: false, stub: "com.frezrik.jiagu.StubApp", stub2: "", lib: ["libjiagu.so"], assets: [], handler: "删除com.frezrik.jiagu包 + libjiagu.so" },
  { name: "Google加固(PairIP)", sample: true, stub: "com.pairip.application.Application", stub2: "", lib: ["libpairipcore.so"], assets: ["4owCveHemXqr7zMk", "CfPdr6NieZZPmy5s", "Cj1Rpx5Vji0dU6ev", "Cn2gBJ7UZJ3lQAKP", "D1aRhGLvXw6v5Tfc", "FS1zxbT23JgpQMHH", "IvHwXY1kJs0BeMbB", "IwxfQMS86237HwXB", "K5gh6oDhylso8NDP", "L0KN0En9uK5FJ58o", "N5XPCIutg3OVkeXm", "NIG3XyFEmzW6fMo3", "SLOukB0aDb3mF0Wg", "ZMVdMzhpjddSEsGx", "aPnlEepwCCgPlUGU", "bakCjDzzYsptCOSi", "cSzpVHFO3xJFhGOY", "cdUCk4tBHyzvbNFz", "e5iRHVM417S4y27D", "epvui228TRjmTvIu", "i0aZicS5LhzUZ1qa", "jne5a7R6y7HZuYEK", "kFgkY8tWg3qHzceg", "klReBY1qZ0n2k0Iy", "lssZoHtq8QOEsHqC", "oOq6NoQpcWlyWupB", "taPjI4cvX7ytH6GW", "uvWfPt7wbhlrrbT0", "wMTBtpemsPZSTxjr", "xz4lE6uu8w0ui1id"], handler: "删除com.pairip包 + libpairipcore.so + 随机命名assets文件" },
  { name: "Nesun", sample: true, stub: "com.nesun.stub.ZAP", stub2: "", lib: ["libzprotect.so"], assets: ["origin.apk"], handler: "删除com.nesun.stub包 + libzprotect.so + origin.apk" },
  { name: "OPPO加固", sample: true, stub: "com.omes.omas.ProxyApplication", stub2: "", lib: ["libomas.so"], assets: ["classes1.png", "classes2.png", "classes3.png", "classes4.png", "classes5.png", "classes6.png"], handler: "删除com.omes.omas包 + libomas.so + classes*.png(加密dex)" },
  { name: "ShadowSafety", sample: true, stub: "v.m.p", stub2: "", lib: ["libshadowsafety.so"], assets: ["libShadowSafetyProtect.so", "libShadowSafetyProtect_a64.so", "libShadowSafetyProtect_enc.so", "libShadowSafetyProtect_mips.a", "libShadowSafetyProtect_x64.so", "libShadowSafetyProtect_x86.so"], handler: "VMP型；优先绕过校验；删v.m.p桩类需保证业务类已还原" },
  { name: "TiamoMuxue(无样本)", sample: false, stub: "com.muxue.xue", stub2: "", lib: ["libTiamo.so", "libTiamoMuxue.so", "libmuxue.so"], assets: ["沐雪"], handler: "删除com.muxue包 + libTiamo*.so + libmuxue.so" },
  { name: "几维安全", sample: true, stub: "com.kiwivm.security.StubApplication", stub2: "", lib: ["libKwProtectSDK.so", "libkwsdataenc.so"], assets: ["39285EFA.dex", "40805.dat", "ec_dt.lic", "notplugmap*.dex", "notplugmap*.db"], handler: "删除桩类 + KwProtectSDK/kwsdataenc so + .dex/.dat/.lic壳数据" },
  { name: "娜迦加固", sample: true, stub: "com.stub.StubApp", stub2: "", lib: ["libxloader.so"], assets: ["maindata/"], handler: "注意与360加固同桩类名com.stub.StubApp！用libxloader.so/maindata区分；删桩类+libxloader.so+maindata" },
  { name: "支付宝加固", sample: true, stub: "com.ashield.Stub", stub2: "", lib: ["libashield.so", "libashieldAdapter.so", "libsign.so"], assets: [], handler: "删除com.ashield包 + libashield*.so；libsign.so确认非业务签名库后再定" },
  { name: "易固", sample: true, stub: "hehua.StubApp", stub2: "", lib: ["libjgdtc.so", "libjiagu.so", "libvmp.so"], assets: [], handler: "删除hehua包 + libjgdtc/libjiagu/libvmp" },
  { name: "梆梆加固(普通)", sample: true, stub: "com.SecShell.SecShell.AW", stub2: "", lib: ["libSecShell.so", "libSecShell-x86.so"], assets: ["classes0.jar", "meta-data/manifest.mf", "meta-data/rsa.pub", "meta-data/rsa.sig"], handler: "删除AW类 + classes0.jar + meta-data壳证书" },
  { name: "梆梆企业", sample: true, stub: "com.secneo.apkwrapper.AW", stub2: "com.secneo.apkwrapper.AP", lib: ["libDexHelper.so", "libDexHelper-x86.so", "libdexjni.so"], assets: [], handler: "删除com.secneo全包 + CP provider + libDexHelper*.so + libdexjni.so" },
  { name: "深思数盾", sample: true, stub: "v5f259fe1.l5f259fe1", stub2: "", lib: [], assets: ["l5f259fe1_a64.so", "l5f259fe1_x64.so"], handler: "删除v5f259fe1.l5f259fe1桩类 + l5f259fe1*.so(包名随版本变)" },
  { name: "爱加密", sample: true, stub: "s.h.e.l.l.S", stub2: "s.h.e.l.l.A", lib: [], assets: ["af.bin", "ijiami.ajm", "signed.bin", "ijm_lib/"], handler: "删除s.h.e.l.l全包 + ijiami.ajm + ijm_lib + af.bin + signed.bin" },
  { name: "爱加密企业", sample: true, stub: "s.h.e.l.l.S", stub2: "", lib: ["libijmDataEncryption.so", "libijmDataEncryption_arm64.so", "libijmDataEncryption_x86.so", "libijmDataEncryption_x86_64.so"], assets: ["IJMDal.Data", "ijiami.ajm", "ijiami.dat"], handler: "删除s.h.e.l.l全包 + ijiami.dat + IJMDal.Data + libijmDataEncryption*.so" },
  { name: "阿里加固", sample: true, stub: "com.ali.mobisecenhance.ld.StubApplication", stub2: "", lib: ["libALBiometricsJni.so", "libalivcffmpeg.so", "libalisecuritysdk.so", "libalijtca_plus.so"], assets: ["ali_sec.dat", "alibaba_version"], handler: "删除com.ali.mobisecenhance包 + ali_sec.dat + alijtca_plus so" },
  { name: "腾讯御安全", sample: true, stub: "StubWrapperProxyApplication", stub2: "", lib: ["libshell-super+包名.so", "libshella-x.y.z.so"], assets: ["0OO00l111l1l", "0OO00oo01l1l", "0OO00oo11l1l", "o0oooOO0ooOo.dat", "t86", "t86_64", "tosversion"], handler: "删除StubWrapperProxyApplication桩类 + 0OO00*文件 + t86/t86_64/tosversion + libshell-super/libshella so" },
  { name: "腾讯御安全企业", sample: true, stub: "(代码被抽取)", stub2: "", lib: ["libshell-superv.2019.so", "libshell-supervbasic.2019.so"], assets: ["0OO00oo01l1l", "0OO00oo11l1l", "dexMethod_00oo1l1l.dat"], handler: "抽取型壳,几乎每方法被抽;优先脱壳回填方法体;删dexMethod数据文件+libshell-superv so" },
  { name: "网易易盾(普通版)", sample: true, stub: "com.netease.android.protect.StubApp", stub2: "", lib: ["libnesec.so", "libnesec-x86.so", "libunisec.so"], assets: ["_ntcfg_.data"], handler: "删除桩类 + _ntcfg_.data + libnesec*.so + libunisec.so" },
  { name: "网易易盾(高级版)", sample: true, stub: "com.netease.nis.wrapper.MyApplication", stub2: "", lib: ["libnesec.so", "libnesec-x86.so"], assets: ["nedata.db"], handler: "删除桩类 + nedata.db + libnesec*.so" },
  { name: "落叶加固(开源版)", sample: true, stub: "com.luoyesiqiu.shell.ProxyApplication", stub2: "com.luoyesiqiu.shell.ProxyComponentFactory", lib: [], assets: ["OoooooOooo", "d_shell_data_001", "vwwwwwvwww/"], handler: "删除com.luoyesiqiu.shell包 + appComponentFactory + OoooooOooo/d_shell_data_001" },
  { name: "落叶加固(魔改版)", sample: true, stub: "4b089d578346008b.ProxyApplication", stub2: "4b089d578346008b.ProxyComponentFactory", lib: [], assets: ["OoooooOooo", "app_acf", "app_name", "vwwwwwvwww/"], handler: "桩类包名随机16位hex;按Manifest实际名字删对应包" },
  { name: "蛮犀加固", sample: true, stub: "com.mx.shell.MXApplication", stub2: "com.mx.shell.MXAppComponentFactory", lib: ["libmxldd.so"], assets: [], handler: "删除com.mx.shell包 + appComponentFactory + libmxldd.so" },
  { name: "随风加固", sample: true, stub: "cn.beingyi.sub.apps.SubApp.SubApplication", stub2: "", lib: [], assets: ["src/"], handler: "删除cn.beingyi.sub包 + src/壳数据" },
  { name: "顶象加固", sample: true, stub: "com.security.shell.V5App", stub2: "com.security.shell.V5App$18", lib: ["libapk0000.so", "libstub000.so"], assets: ["dsnapk0000.vd", "dsnstub000.vd", "2ef03a36", "csnb4adab14.data", "output-arm64-v8a.zip"], handler: "删除com.security.shell包 + .vd文件 + libapk0000/libstub000 so" },
  { name: "APKProtect(无样本)", sample: false, stub: "", stub2: "", lib: ["libAPKProtect.so"], assets: [], handler: "无样本壳;按实际Manifest桩类+特征文件libAPKProtect.so处理" },
  { name: "AppSealin(无样本)", sample: false, stub: "", stub2: "", lib: ["libcovault.so", "libcovault-appsec.so"], assets: [], handler: "无样本壳;按实际Manifest桩类+libcovault*.so处理" },
  { name: "AppShield(无样本)", sample: false, stub: "", stub2: "", lib: ["libahope.so"], assets: [], handler: "无样本壳;按实际Manifest桩类+libahope.so处理" },
  { name: "Master-Mu(无样本)", sample: false, stub: "", stub2: "", lib: [], assets: [], handler: "仅占位信息(无公开样本特征)" },
  { name: "UU安全(无样本)", sample: false, stub: "", stub2: "", lib: ["libuusafe.so", "libuusafe.jar.so", "libuusafeempty.so"], assets: [], handler: "无样本壳;按实际Manifest桩类+libuusafe*.so处理" },
  { name: "中国移动加固(无样本)", sample: false, stub: "", stub2: "", lib: [], assets: ["mogosec_classes", "libmogosecurity.so", "libmogosec_dex.so", "libmogosec_so", "libcmvmp.so", "decrypt.so", "mogosec_data"], handler: "无样本壳;删除mogosec_*全家桶特征文件" },
  { name: "启明星辰", sample: true, stub: "", stub2: "", lib: [], assets: ["signCache/enc.mf", "venCache/classes*.dex", "venCache/libvenSec*.so", "venCache/libsqlen_venus*.so", "venCache/libvenustech*.so", "venCache/venus0", "venCache/venusmd", "venCache/venusrc", "venCache/venusrd", "venCache/version"], handler: "删除signCache/enc.mf + venCache/壳数据(classes*.dex+libvenSec*+libsqlen_venus*+libvenustech*+venus*) " },
  { name: "新百度加固", sample: true, stub: "", stub2: "", lib: ["libbaiduprotect.so", "libbaiduprotect_sdk-*.so"], assets: ["baiduprotect-sec.dex", "baiduprotect.md", "baiduprotect*.i.dex", "baiduprotect*.jar"], handler: "删除baiduprotect*.dex/jar/md + libbaiduprotect*.so" },
  { name: "百度加固企业(无样本)", sample: false, stub: "", stub2: "", lib: ["libbaiduprotect.so"], assets: ["baiduprotect.m", "baiduprotect*.jar", "baiduprotectmac-*"], handler: "无样本壳;删除baiduprotect.m/*.jar + libbaiduprotect.so" },
  { name: "海云安(无样本)", sample: false, stub: "", stub2: "", lib: ["libsecidea.so"], assets: ["secdata1.dat", "secdata2.dat"], handler: "无样本壳;删除secdata*.dat + libsecidea.so" },
  { name: "珊瑚灵御(无样本)", sample: false, stub: "", stub2: "", lib: [], assets: ["libreincp.so", "libreincp_x86.so"], handler: "无样本壳;删除libreincp*.so" },
  { name: "瑞星加固(无样本)", sample: false, stub: "", stub2: "", lib: ["librsprotect.so"], assets: [], handler: "无样本壳;删除librsprotect.so" },
  { name: "盛大加固(无样本)", sample: false, stub: "", stub2: "", lib: [], assets: ["libapssec.so"], handler: "无样本壳;删除libapssec.so" },
  { name: "网秦加固(无样本)", sample: false, stub: "", stub2: "", lib: ["libnqshield.so"], assets: [], handler: "无样本壳;删除libnqshield.so" },
  { name: "腾讯加固(无样本)", sample: false, stub: "", stub2: "", lib: ["libshell-super*.so"], assets: ["0OO00l111l1l", "o0oooOO0ooOo.dat", "tosversion", "tencent_stub"], handler: "无样本壳;删除0OO00*+o0oooOO0ooOo.dat+tosversion+tencent_stub+libshell-super*.so" },
  { name: "通付盾(无样本)", sample: false, stub: "", stub2: "", lib: ["libegis.so", "libegis-x86.so", "libegis_security.so", "libegis_sls.so"], assets: ["libegis.a", "virtual"], handler: "无样本壳;删除libegis*.so+libegis.a/mode/virtual" },
  { name: "阿里聚安全(无样本)", sample: false, stub: "", stub2: "", lib: [], assets: ["aliprotect.dat", "dingtalkttid"], handler: "无样本壳;删除aliprotect.dat+dingtalkttid" }
];

  function norm(s) { return String(s||'').replace(/\./g,'').toLowerCase(); }
  // 特征匹配：子串匹配，但特征长度>=3才生效，避免超短特征误报
  function has(sub, list) { return (list||[]).some(function(x){ var nx=norm(x); return nx.length>=3 && (sub.indexOf(nx)>=0); }); }

  // 按桩类精确匹配(兼容去掉点号)
  function byStub(stub) {
    if (!stub) return [];
    const n = norm(stub);
    return DB.filter(function(s){ return norm(s.stub) === n; });
  }

  // 按特征文件匹配(so/assets 做子串匹配)
  function byFeature(feature) {
    if (!feature) return [];
    const n = norm(feature);
    return DB.filter(function(s){
      return has(n, s.lib) || has(n, s.assets);
    });
  }

  // 综合判定：桩类精确+lib/assets加权
  function combined(stubClass, libs, assets) {
    const score = [];
    const libList = libs ? JSON.parse(libs) : [];
    const assetsList = assets ? JSON.parse(assets) : [];
    DB.forEach(function(s){
      let sc = 0, hits = [];
      if (stubClass && norm(s.stub) === norm(stubClass)) { sc += 100; hits.push('桩类:'+s.stub); }
      libList.forEach(function(l){
        const nl = norm(l);
        (s.lib||[]).forEach(function(sl){ var nsl=norm(sl); if (nsl.length>=3 && nl.length>=3 && (nsl.indexOf(nl)>=0 || nl.indexOf(nsl)>=0)){ sc += 20; hits.push('lib:'+l); } });
      });
      assetsList.forEach(function(a){
        const na = norm(a);
        (s.assets||[]).forEach(function(sa){ var nsa=norm(sa); if (nsa.length>=3 && na.length>=3 && (nsa.indexOf(na)>=0 || na.indexOf(nsa)>=0)){ sc += 15; hits.push('assets:'+a); } });
      });
      if (sc > 0) score.push({ name: s.name, sample: s.sample, score: sc, hits: hits, handler: s.handler, stub: s.stub, stub2: s.stub2, lib: s.lib, assets: s.assets });
    });
    score.sort(function(a,b){ return b.score - a.score; });
    return score;
  }

  function fmt(list) {
    return list.map(function(s){
      return {
        shell: s.name,
        有样本: s.sample ? '是' : '否',
        桩类: s.stub || '(无/抽取)',
        代理类: s.stub2 || '',
        特征so: s.lib || [],
        特征assets: s.assets || [],
        处置路线: s.handler
      };
    });
  }

  async function identify_by_stub(p) {
    const r = byStub(p.stubClass);
    return { 查询桩类: p.stubClass, 匹配数: r.length, 结果: fmt(r) };
  }

  async function identify_by_feature(p) {
    const r = byFeature(p.feature);
    return { 查询特征: p.feature, 匹配数: r.length, 结果: fmt(r) };
  }

  async function identify_combined(p) {
    const r = combined(p.stubClass, p.libs, p.assets);
    return { 综合判定: true, 匹配数: r.length, 按得分排序: r.map(function(x){ return { shell: x.name, 得分: x.score, 命中项: x.hits, 有样本: x.sample?'是':'否', 处置路线: x.handler }; }) };
  }

  return { identify_by_stub, identify_by_feature, identify_combined };
})();

exports.identify_by_stub = hardeningDB.identify_by_stub;
exports.identify_by_feature = hardeningDB.identify_by_feature;
exports.identify_combined = hardeningDB.identify_combined;