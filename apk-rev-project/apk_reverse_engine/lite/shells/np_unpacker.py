# -*- coding: utf-8 -*-
"""np 加固（NP管理器加密资源）解密器

来源：np资源解密1.1.py（原样算法移植，未改动任何加密逻辑）
支持：
  1) 加密资源文件 3.0 / 加密资源文件增强版 3.0 —— 从 dex 提取 base64 密钥并用 RSA 私钥还原 zip 资源
  2) 加密资源文件内容 —— 遍历 assets/*.dat，用包名 XOR 还原
"""
import os, re, io, sys, struct, zlib, zipfile, base64, urllib.parse

_a = set(range(48, 58)) | set(range(65, 91)) | set(range(97, 123)) | {43, 61}


def _b(c, d): return struct.unpack_from('<H', c, d)[0]
def _e(c, d): return struct.unpack_from('<I', c, d)[0]


def _h(i, j):
    k = _b(i, j + 2); l = _e(i, j + 4); m = _e(i, j + 8); n = _e(i, j + 16); o = _e(i, j + 20)
    p = j + k; q = j + o; r = bool(n & 0x100); s = []
    def t(u):
        v = i[u]
        if v & 0x80: return ((v & 0x7F) << 8) | i[u + 1], u + 2
        return v, u + 1
    def w(u):
        v = _b(i, u)
        if v & 0x8000: return ((v & 0x7FFF) << 16) | _b(i, u + 2), u + 4
        return v, u + 2
    for x in range(m):
        y = _e(i, p + x * 4); z = q + y
        if r:
            _, z = t(z); aa, z = t(z); ab = i[z: z + aa]
            s.append(ab.decode("utf-8", errors="ignore"))
        else:
            ac, z = w(z); ab = i[z: z + ac * 2]
            s.append(ab.decode("utf-16le", errors="ignore"))
    return s


def _ad(i):
    if i.lstrip().startswith(b"<"):
        m = re.search(r'package="([^"]+)"', i.decode("utf-8", errors="ignore"))
        if m: return m.group(1)
        return None
    if len(i) < 8 or _b(i, 0) != 0x0003: return None
    j = _b(i, 2); s = None
    while j + 8 <= len(i):
        k = _b(i, j); l = _e(i, j + 4)
        if l < 8 or j + l > len(i): break
        if k == 0x0001: s = _h(i, j)
        elif k == 0x0102 and s:
            m = _e(i, j + 20)
            if m < len(s) and s[m] == "manifest":
                n = _b(i, j + 24); o = _b(i, j + 26); p = _b(i, j + 28); q = j + 16 + n
                for x in range(p):
                    y = q + x * o; z = _e(i, y + 4); aa = _e(i, y + 8); ab = i[y + 15]; ac = _e(i, y + 16)
                    if z < len(s) and s[z] == "package":
                        ad2 = aa if aa != 0xFFFFFFFF else ac if ab == 3 else 0xFFFFFFFF
                        if ad2 < len(s): return s[ad2]
        j += l
    return None


def _ae(af):
    z = zipfile.ZipFile(af)
    try: ag = _ad(z.read('AndroidManifest.xml'))
    except Exception: ag = None
    if ag and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.]*', ag): return ag
    return re.sub(r'[^A-Za-z0-9_.]', '_', os.path.splitext(os.path.basename(af))[0])


def _ah(i, j):
    k = i[j]; j += 1; l = i[j]; j += 1
    if l & 0x80:
        m = l & 0x7f; l = int.from_bytes(i[j:j + m], 'big'); j += m
    return k, l, j


def _ai(i):
    j = []; k = 0
    while k < len(i):
        l, m, n = _ah(i, k); j.append((l, i[n:n + m])); k = n + m
    return j


def _aj(ak):
    try:
        al = _ai(_ai(ak)[0][1]); am = None
        for an, ao in al:
            if an == 0x04: am = ao; break
        if am is None: return None
        ap = [int.from_bytes(aq[1], 'big') for aq in _ai(_ai(am)[0][1])]
        if len(ap) < 4: return None
        return ap[1], ap[3]
    except Exception: return None


def _ar(as_, at, au):
    av = b''
    for aw in range(0, len(as_), 128):
        ax = pow(int.from_bytes(as_[aw:aw + 128], 'big'), au, at).to_bytes(128, 'big')
        ay = ax.find(b'\x00', 2)
        if ay == -1: return None
        av += ax[ay + 1:]
    return av


def _az(ba, bb):
    bc = len(bb); return bytes(ba[bd] ^ bb[bd % bc] for bd in range(len(ba)))


def _be(ba, bb, bc=1024000):
    bd = len(bb); be_ = (bb * (bc // bd + 1))[:bc]; bf = bytearray()
    for bg in range(0, len(ba), bc):
        bh = ba[bg:bg + bc]
        if not bh: break
        bi = be_[:len(bh)]; bj = int.from_bytes(bh, 'big') ^ int.from_bytes(bi, 'big')
        bf += bj.to_bytes(len(bh), 'big')
    return bytes(bf)


def _bk(bl, bm): return ''.join(chr(bn ^ bm) for bn in bl)


def _bo(bp):
    bq = 0; br = -1
    for bs in range(256):
        bt = sum(1 for bu in bp[:800] if (bu & 0xff) ^ bs in _a)
        if bt > br: br = bt; bq = bs
    return bq


def _bv(bw):
    for bx in ([1606] if bw else []):
        by = _bk(bw, bx); bz = re.match(rb'[A-Za-z0-9+/]+={0,2}', by.encode('latin1', 'ignore'))
        if bz:
            try:
                ca = base64.b64decode(bz.group())
                if ca[:2] == b'\x30\x82' and _aj(ca): return ca
            except Exception: pass
    cb = _bo(bw)
    for cc in range(256):
        bx = (cc << 8) | cb; by = _bk(bw, bx); bz = re.match(rb'[A-Za-z0-9+/]+={0,2}', by.encode('latin1', 'ignore'))
        if bz:
            try:
                ca = base64.b64decode(bz.group())
                if ca[:2] == b'\x30\x82' and _aj(ca): return ca
            except Exception: pass
    return None


def _cd(ce):
    cf = []; cg = 0
    while True:
        ch = ce.find(b'\x00\x03\x02\x00', cg)
        if ch == -1: break
        ci = int.from_bytes(ce[ch + 4:ch + 8], 'little')
        if 0 < ci < 500000 and ch + 8 + ci * 2 <= len(ce):
            cj = [int.from_bytes(ce[ch + 8 + ck * 2:ch + 10 + ck * 2], 'little', signed=True) for ck in range(ci)]
            cf.append(cj)
        cg = ch + 4
    return cf


def _cl(cm):
    for cn in _cd(cm):
        if not (300 <= len(cn) <= 2000): continue
        co = [cp & 0xffff for cp in cn]; cq = _bv(co)
        if cq: return cq
    return None


def _cr(cs):
    ct = []
    for cu in re.finditer(rb'[A-Za-z0-9+/]{80,}={0,2}', cs):
        cv = cu.group()
        try: cw = base64.b64decode(cv)
        except Exception: continue
        if len(cw) in (640, 768): ct.append(cw)
    return ct


def _run_np_resource(apk_path, out_dir, _log=None):
    """NP 加密资源文件 3.0 / 增强版 3.0 解包。
    返回 dict：{ok, version, package, xor_key, files, zip_path, note}"""
    log = _log or (lambda s: print(s))
    result = {'ok': False, 'version': '', 'package': '', 'xor_key': '', 'files': [], 'zip_path': '', 'note': ''}
    da = zipfile.ZipFile(apk_path)
    db = None
    for dc in da.namelist():
        if len(dc) > 500: db = dc; break
    if db is None: return result
    dd = da.read(next(de for de in da.namelist() if de.endswith('.dex')))
    df = _cl(dd)
    if not df: return result
    dg = _aj(df)
    if not dg: return result
    dh, di = dg
    dj = _cr(dd); dk = None
    for dl in dj:
        dm = _ar(dl, dh, di)
        if dm and b'=' in urllib.parse.unquote_to_bytes(dm):
            dk = urllib.parse.unquote(dm.decode('latin1')); break
    if not dk: return result
    dn = {}
    for dp in dk.splitlines():
        if '=' in dp:
            dq, dr = dp.split('=', 1); dn[dq] = dr.strip()
    if 'c' not in dn: return result
    ds = base64.b64decode(dn['c']); dt = _ar(ds, dh, di)
    if not dt: return result
    du = da.read(db); dv = bytearray(du[:8]) + bytearray(_be(du[8:], dt))
    dw = dv.find(b'PK\x03\x04')
    if dw == -1: return result
    dx = _ae(apk_path)
    dy = zipfile.ZipFile(io.BytesIO(bytes(dv[dw:])))
    dz = sorted((ea for ea in dy.namelist() if not ea.endswith('/')), key=str.lower)
    if any(ea.startswith('bsh/') or ea.startswith('kotlin/') or ea == 'DebugProbesKt.bin' for ea in dz):
        eb = '加密资源文件增强版3.0'
    else:
        eb = '加密资源文件3.0'

    ec = []
    ec.append('源文件: ' + os.path.basename(apk_path))
    ec.append('包名: ' + dx)
    ec.append('版本: ' + eb)
    ec.append('XOR密钥: ' + dt.decode('latin1'))
    ec.append('还原文件: 共%d个' % len(dz))
    ec.append('资源列表:')
    for ea in dz: ec.append('  /' + ea)
    ed = '\n'.join(ec) + '\n'

    ee = os.path.join(out_dir, 'np管理器资源解密', dx); os.makedirs(ee, exist_ok=True)
    ef = io.BytesIO()
    with zipfile.ZipFile(ef, 'w', zipfile.ZIP_STORED) as eg:
        for ea in dz: eg.writestr(ea, dy.read(ea))
        eg.writestr('说明.txt', ed.encode('utf-8'))
    zip_path = os.path.join(ee, dx + '.zip')
    with open(zip_path, 'wb') as eh: eh.write(ef.getvalue())
    log('版本: ' + eb)
    log('还原文件: 共%d个' % len(dz))
    for ea in dz: log('  /' + ea)
    result.update(ok=True, version=eb, package=dx, xor_key=dt.decode('latin1'), files=list(dz), zip_path=zip_path)
    return result


def _run_np_content(apk_path, out_dir, _log=None):
    """NP 加密资源文件内容解包。返回结构化 dict。"""
    log = _log or (lambda s: print(s))
    result = {'ok': False, 'version': '加密资源文件内容', 'package': '', 'xor_key': '', 'files': [], 'zip_path': '', 'note': ''}
    da = zipfile.ZipFile(apk_path)
    ek = [ea for ea in da.namelist() if ea.startswith('assets/') and ea.endswith('.dat')]
    if not ek: return result
    el = ek[0]; dx = _ae(apk_path); dt = None; em = None
    for en in range(21, 129):
        eo = (dx.encode() * 8)[:en]; ep = _az(da.read(el), eo); ec = ep.split(b'\n')
        if len(ec) >= 2 and all(re.fullmatch(rb'[^\x00-\x1f\x7f]+', eq) for eq in ec if eq):
            er = []; es = True
            for eq in ec:
                if not eq: continue
                et = eq.decode()
                try: da.getinfo('assets/' + et); er.append(et)
                except KeyError: es = False
            if er and es: dt = eo; em = er; break
    if not dt: return result
    eu = dt
    def ev(ew, ex):
        ey = len(ew); ez = (ex * (ey // len(ex) + 1))[:ey]
        return (int.from_bytes(ew, 'big') ^ int.from_bytes(ez, 'big')).to_bytes(ey, 'big')
    def fa(fb, ex, fc=1024000):
        fd = bytearray()
        for fe in range(0, len(fb), fc): fd += ev(fb[fe:fe + fc], ex)
        return bytes(fd)
    def ff(fg): return len(zlib.compress(fg[:131072], 9))

    ee = os.path.join(out_dir, 'np管理器内容解密', dx); os.makedirs(ee, exist_ok=True)
    fh = sorted(em, key=str.lower); ec = []
    ec.append('源文件: ' + os.path.basename(apk_path))
    ec.append('包名: ' + dx)
    ec.append('版本: 加密资源文件内容')
    ec.append('密钥: ' + eu.decode('latin1'))
    ec.append('还原文件: 共%d个' % len(fh))
    ec.append('资源列表:')
    for et in fh: ec.append('/assets/' + et)
    ed = '\n'.join(ec) + '\n'
    ef = io.BytesIO()
    with zipfile.ZipFile(ef, 'w', zipfile.ZIP_STORED) as fi:
        for et in fh:
            fj = da.read('assets/' + et)
            fk = [(fa(fj, eu), 'pkg块'), (ev(fj, b'a'), 'xor-a'), (fj, '原样')]
            fk.sort(key=lambda fl: ff(fl[0]))
            fi.writestr('assets/' + et, fk[0][0])
        fi.writestr('说明.txt', ed.encode('utf-8'))
    zip_path = os.path.join(ee, dx + '.zip')
    with open(zip_path, 'wb') as eh: eh.write(ef.getvalue())
    log('版本: 加密资源文件内容'); log('还原文件: 共%d个' % len(em))
    for et in fh: log('/assets/' + et)
    result.update(ok=True, package=dx, xor_key=eu.decode('latin1'), files=list(fh), zip_path=zip_path)
    return result


def detect(np_like, _log=None):
    """判断是否 NP 加固：dex 中是否含 base64 RSA 私钥且能提取 XOR key。"""
    try:
        da = zipfile.ZipFile(np_like)
        if not any(n.endswith('.dex') for n in da.namelist()): return False
        dd = da.read(next(n for n in da.namelist() if n.endswith('.dex')))
        df = _cl(dd)
        return df is not None
    except Exception:
        return False


def unpack(np_like, out_dir, log=None):
    """NP 解包入口：优先尝试『加密资源文件 3.0』，失败则回退『加密资源文件内容』。"""
    if not os.path.isfile(np_like):
        return {'ok': False, 'shell': 'np', 'note': '文件不存在'}
    r1 = _run_np_resource(np_like, out_dir, log)
    if r1['ok']:
        r1['shell'] = 'np'
        r1['mode'] = 'resource'
        return r1
    r2 = _run_np_content(np_like, out_dir, log)
    if r2['ok']:
        r2['shell'] = 'np'
        r2['mode'] = 'content'
        return r2
    return {'ok': False, 'shell': 'np', 'note': '未识别或解密失败'}


def main(np_like):
    """CLI 兼容入口"""
    fn = np_like if np_like else (sys.argv[1] if len(sys.argv) > 1 else input('请输入APK路径: ').strip())
    if not os.path.isfile(fn):
        print('文件不存在'); return
    out = '/storage/emulated/0' if os.path.isdir('/storage/emulated/0') else os.getcwd()
    r = unpack(fn, out)
    if r.get('ok'): print('解密完成')
    else: print('未识别或解密失败')


if __name__ == '__main__':
    main(' '.join(sys.argv[1:]).strip().strip('"').strip("'"))
