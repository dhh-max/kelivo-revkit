import sys, os, re, io, struct, zlib, zipfile, base64, urllib.parse
a = set(range(48, 58)) | set(range(65, 91)) | set(range(97, 123)) | {43, 61}
def b(c, d): return struct.unpack_from('<H', c, d)[0]
def e(c, d): return struct.unpack_from('<I', c, d)[0]
f = 0x100
g = 0xFFFFFFFF
def h(i, j):
    k = b(i, j + 2); l = e(i, j + 4); m = e(i, j + 8); n = e(i, j + 16); o = e(i, j + 20)
    p = j + k; q = j + o; r = bool(n & f); s = []
    def t(u):
        v = i[u]
        if v & 0x80: return ((v & 0x7F) << 8) | i[u + 1], u + 2
        return v, u + 1
    def w(u):
        v = b(i, u)
        if v & 0x8000: return ((v & 0x7FFF) << 16) | b(i, u + 2), u + 4
        return v, u + 2
    for x in range(m):
        y = e(i, p + x * 4); z = q + y
        if r:
            _, z = t(z); aa, z = t(z); ab = i[z: z + aa]
            s.append(ab.decode("utf-8", errors="ignore"))
        else:
            ac, z = w(z); ab = i[z: z + ac * 2]
            s.append(ab.decode("utf-16le", errors="ignore"))
    return s
def ad(i):
    if i.lstrip().startswith(b"<"):
        m = re.search(r'package="([^"]+)"', i.decode("utf-8", errors="ignore"))
        if m: return m.group(1)
        return None
    if len(i) < 8 or b(i, 0) != 0x0003: return None
    j = b(i, 2); s = None
    while j + 8 <= len(i):
        k = b(i, j); l = e(i, j + 4)
        if l < 8 or j + l > len(i): break
        if k == 0x0001: s = h(i, j)
        elif k == 0x0102 and s:
            m = e(i, j + 20)
            if m < len(s) and s[m] == "manifest":
                n = b(i, j + 24); o = b(i, j + 26); p = b(i, j + 28); q = j + 16 + n
                for x in range(p):
                    y = q + x * o; z = e(i, y + 4); aa = e(i, y + 8); ab = i[y + 15]; ac = e(i, y + 16)
                    if z < len(s) and s[z] == "package":
                        ad2 = aa if aa != g else ac if ab == 3 else g
                        if ad2 < len(s): return s[ad2]
        j += l
    return None
def ae(af):
    z = zipfile.ZipFile(af)
    try: ag = ad(z.read('AndroidManifest.xml'))
    except Exception: ag = None
    if ag and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.]*', ag): return ag
    return re.sub(r'[^A-Za-z0-9_.]', '_', os.path.splitext(os.path.basename(af))[0])
def ah(i, j):
    k = i[j]; j += 1; l = i[j]; j += 1
    if l & 0x80:
        m = l & 0x7f; l = int.from_bytes(i[j:j + m], 'big'); j += m
    return k, l, j
def ai(i):
    j = []; k = 0
    while k < len(i):
        l, m, n = ah(i, k); j.append((l, i[n:n + m])); k = n + m
    return j
def aj(ak):
    try:
        al = ai(ai(ak)[0][1]); am = None
        for an, ao in al:
            if an == 0x04: am = ao; break
        if am is None: return None
        ap = [int.from_bytes(aq[1], 'big') for aq in ai(ai(am)[0][1])]
        if len(ap) < 4: return None
        return ap[1], ap[3]
    except Exception: return None
def ar(as_, at, au):
    av = b''
    for aw in range(0, len(as_), 128):
        ax = pow(int.from_bytes(as_[aw:aw + 128], 'big'), au, at).to_bytes(128, 'big')
        ay = ax.find(b'\x00', 2)
        if ay == -1: return None
        av += ax[ay + 1:]
    return av
def az(ba, bb):
    bc = len(bb); return bytes(ba[bd] ^ bb[bd % bc] for bd in range(len(ba)))
def be(ba, bb, bc=1024000):
    bd = len(bb); be_ = (bb * (bc // bd + 1))[:bc]; bf = bytearray()
    for bg in range(0, len(ba), bc):
        bh = ba[bg:bg + bc]
        if not bh: break
        bi = be_[:len(bh)]; bj = int.from_bytes(bh, 'big') ^ int.from_bytes(bi, 'big')
        bf += bj.to_bytes(len(bh), 'big')
    return bytes(bf)
def bk(bl, bm): return ''.join(chr(bn ^ bm) for bn in bl)
def bo(bp):
    bq = 0; br = -1
    for bs in range(256):
        bt = sum(1 for bu in bp[:800] if (bu & 0xff) ^ bs in a)
        if bt > br: br = bt; bq = bs
    return bq
def bv(bw):
    for bx in ([1606] if bw else []):
        by = bk(bw, bx); bz = re.match(rb'[A-Za-z0-9+/]+={0,2}', by.encode('latin1', 'ignore'))
        if bz:
            try:
                ca = base64.b64decode(bz.group())
                if ca[:2] == b'\x30\x82' and aj(ca): return ca
            except Exception: pass
    cb = bo(bw)
    for cc in range(256):
        bx = (cc << 8) | cb; by = bk(bw, bx); bz = re.match(rb'[A-Za-z0-9+/]+={0,2}', by.encode('latin1', 'ignore'))
        if bz:
            try:
                ca = base64.b64decode(bz.group())
                if ca[:2] == b'\x30\x82' and aj(ca): return ca
            except Exception: pass
    return None
def cd(ce):
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
def cl(cm):
    for cn in cd(cm):
        if not (300 <= len(cn) <= 2000): continue
        co = [cp & 0xffff for cp in cn]; cq = bv(co)
        if cq: return cq
    return None
def cr(cs):
    ct = []
    for cu in re.finditer(rb'[A-Za-z0-9+/]{80,}={0,2}', cs):
        cv = cu.group()
        try: cw = base64.b64decode(cv)
        except Exception: continue
        if len(cw) in (640, 768): ct.append(cw)
    return ct
def cx(cy, cz):
    da = zipfile.ZipFile(cy); db = None
    for dc in da.namelist():
        if len(dc) > 500: db = dc; break
    if db is None: return False
    dd = da.read(next(de for de in da.namelist() if de.endswith('.dex')))
    df = cl(dd)
    if not df: return False
    dg = aj(df)
    if not dg: return False
    dh, di = dg; dj = cr(dd); dk = None
    for dl in dj:
        dm = ar(dl, dh, di)
        if dm and b'=' in urllib.parse.unquote_to_bytes(dm):
            dk = urllib.parse.unquote(dm.decode('latin1')); break
    if not dk: return False
    dn = {}
    for dp in dk.splitlines():
        if '=' in dp: dq, dr = dp.split('=', 1); dn[dq] = dr.strip()
    if 'c' not in dn: return False
    ds = base64.b64decode(dn['c']); dt = ar(ds, dh, di)
    if not dt: return False
    du = da.read(db); dv = bytearray(du[:8]) + bytearray(be(du[8:], dt))
    dw = dv.find(b'PK\x03\x04')
    if dw == -1: return False
    dx = ae(cy); dy = zipfile.ZipFile(io.BytesIO(bytes(dv[dw:])))
    dz = sorted((ea for ea in dy.namelist() if not ea.endswith('/')), key=str.lower)
    if any(ea.startswith('bsh/') or ea.startswith('kotlin/') or ea == 'DebugProbesKt.bin' for ea in dz):
        eb = '加密资源文件增强版3.0'
    else: eb = '加密资源文件3.0'
    ec = []
    ec.append('源文件: ' + os.path.basename(cy)); ec.append('包名: ' + dx); ec.append('版本: ' + eb)
    ec.append('XOR密钥: ' + dt.decode('latin1')); ec.append('还原文件: 共%d个' % len(dz)); ec.append('资源列表:')
    for ea in dz: ec.append('  /' + ea)
    ed = '\n'.join(ec) + '\n'
    ee = os.path.join(cz, 'np管理器资源解密', dx); os.makedirs(ee, exist_ok=True)
    ef = io.BytesIO()
    with zipfile.ZipFile(ef, 'w', zipfile.ZIP_STORED) as eg:
        for ea in dz: eg.writestr(ea, dy.read(ea))
        eg.writestr('说明.txt', ed.encode('utf-8'))
    with open(os.path.join(ee, dx + '.zip'), 'wb') as eh: eh.write(ef.getvalue())
    print('版本: ' + eb); print('还原文件: 共%d个' % len(dz))
    for ea in dz: print('  /' + ea)
    return True
def ei(ej, cz):
    da = zipfile.ZipFile(ej)
    ek = [ea for ea in da.namelist() if ea.startswith('assets/') and ea.endswith('.dat')]
    if not ek: return False
    el = ek[0]; dx = ae(ej); dt = None; em = None
    for en in range(21, 129):
        eo = (dx.encode() * 8)[:en]; ep = az(da.read(el), eo); ec = ep.split(b'\n')
        if len(ec) >= 2 and all(re.fullmatch(rb'[^\x00-\x1f\x7f]+', eq) for eq in ec if eq):
            er = []; es = True
            for eq in ec:
                if not eq: continue
                et = eq.decode()
                try: da.getinfo('assets/' + et); er.append(et)
                except KeyError: es = False
            if er and es: dt = eo; em = er; break
    if not dt: return False
    eu = dt
    def ev(ew, ex):
        ey = len(ew); ez = (ex * (ey // len(ex) + 1))[:ey]
        return (int.from_bytes(ew, 'big') ^ int.from_bytes(ez, 'big')).to_bytes(ey, 'big')
    def fa(fb, ex, fc=1024000):
        fd = bytearray()
        for fe in range(0, len(fb), fc): fd += ev(fb[fe:fe + fc], ex)
        return bytes(fd)
    def ff(fg): return len(zlib.compress(fg[:131072], 9))
    ee = os.path.join(cz, 'np管理器内容解密', dx); os.makedirs(ee, exist_ok=True)
    fh = sorted(em, key=str.lower); ec = []
    ec.append('源文件: ' + os.path.basename(ej)); ec.append('包名: ' + dx); ec.append('版本: 加密资源文件内容')
    ec.append('密钥: ' + eu.decode('latin1')); ec.append('还原文件: 共%d个' % len(fh)); ec.append('资源列表:')
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
    with open(os.path.join(ee, dx + '.zip'), 'wb') as eh: eh.write(ef.getvalue())
    print('版本: 加密资源文件内容'); print('还原文件: 共%d个' % len(em))
    for et in fh: print('/assets/' + et)
    return True
def fm():
    if len(sys.argv) < 2: fn = input('请输入APK路径: ').strip()
    else: fn = sys.argv[1]
    if not os.path.isfile(fn): print('文件不存在'); return
    cz = '/storage/emulated/0'
    if not os.path.isdir(cz): cz = os.getcwd()
    fo = cx(fn, cz) or ei(fn, cz)
    if fo: print('解密完成')
    else: print('未识别或解密失败')
if __name__ == '__main__':
    fm()