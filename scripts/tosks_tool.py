#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys,os,struct,zipfile,hashlib,zlib,re
try:
    from Crypto.Cipher import AES as _AES
except Exception:
    _AES=None
    print('[提示] 未装 pycryptodome, 纯Python AES较慢; pip install pycryptodome 可提速50倍+')
RCON_H=bytes.fromhex('01020408102040801b36')
SBOX_H=bytes.fromhex('637c777bf26b6fc5')
ISBOX_H=bytes.fromhex('52096ad53036a538')
def a1(a,b):
    p=0
    for _ in range(8):
        if b&1:p^=a
        hi=a&0x80
        a=(a<<1)&0xFF
        if hi:a^=0x1B
        b>>=1
    return p
x1=bytes(a1(0x0e,i) for i in range(256))
x2=bytes(a1(0x09,i) for i in range(256))
x3=bytes(a1(0x0d,i) for i in range(256))
x4=bytes(a1(0x0b,i) for i in range(256))
def a2(s):
    return bytes(s[i] for i in (0,13,10,7,4,1,14,11,8,5,2,15,12,9,6,3))
def a3(rs):
    E,B9,D,BB=x1,x2,x3,x4
    o=bytearray(16)
    for c in range(4):
        i=c*4
        o[i]=E[rs[i]]^BB[rs[i+1]]^D[rs[i+2]]^B9[rs[i+3]]
        o[i+1]=B9[rs[i]]^E[rs[i+1]]^BB[rs[i+2]]^D[rs[i+3]]
        o[i+2]=D[rs[i]]^B9[rs[i+1]]^E[rs[i+2]]^BB[rs[i+3]]
        o[i+3]=BB[rs[i]]^D[rs[i+1]]^B9[rs[i+2]]^E[rs[i+3]]
    return bytes(o)
x5={}
def a4(K,sb,rcon):
    key=(K,sb[:4],rcon[:4])
    c=x5.get(key)
    if c is None:
        w=[int.from_bytes(K[i:i+4],'big') for i in range(0,16,4)]
        for i in range(4,44):
            t=w[i-1]
            if i%4==0:
                t=((t<<8)|(t>>24))&0xFFFFFFFF
                t=int.from_bytes(bytes(sb[b] for b in t.to_bytes(4,'big')),'big')^(rcon[i//4-1]<<24)
            w.append(w[i-4]^t)
        rk=[b''.join(w[i*4+j].to_bytes(4,'big') for j in range(4)) for i in range(11)]
        rkd=[rk[10]]+[a3(rk[r]) for r in range(9,0,-1)]+[rk[0]]
        c=(rk,rkd)
        x5[key]=c
    return c
x6={}
def a5(ib):
    key=ib[:8]
    W=x6.get(key)
    if W is None:
        E,B9,D,BB=x1,x2,x3,x4
        hi=[ib[x] for x in range(256)]
        W=(
            [E[hi[i]]|(B9[hi[i]]<<8)|(D[hi[i]]<<16)|(BB[hi[i]]<<24) for i in range(256)],
            [BB[hi[i]]|(E[hi[i]]<<8)|(B9[hi[i]]<<16)|(D[hi[i]]<<24) for i in range(256)],
            [D[hi[i]]|(BB[hi[i]]<<8)|(E[hi[i]]<<16)|(B9[hi[i]]<<24) for i in range(256)],
            [B9[hi[i]]|(D[hi[i]]<<8)|(BB[hi[i]]<<16)|(E[hi[i]]<<24) for i in range(256)],
        )
        x6[key]=W
    return W
def a6(s,W):
    W0,W1,W2,W3=W
    o=bytearray(16)
    for c in range(4):
        i=c*4
        w=W0[s[i]]^W1[s[i+1]]^W2[s[i+2]]^W3[s[i+3]]
        o[i]=w&0xff
        o[i+1]=(w>>8)&0xff
        o[i+2]=(w>>16)&0xff
        o[i+3]=(w>>24)&0xff
    return bytes(o)
def a7(st,rkd,W,ib):
    s=bytes(a^b for a,b in zip(st,rkd[0]))
    for imr in rkd[1:10]:
        s=a6(a2(s),W)
        s=bytes(a^b for a,b in zip(s,imr))
    s=a2(s)
    s=bytes(ib[x] for x in s)
    return bytes(a^b for a,b in zip(s,rkd[10]))
def a8(ct,key,iv,sb,ib,rc):
    if _AES is not None:
        return _AES.new(key,_AES.MODE_CBC,iv).decrypt(ct[:len(ct)&~15])
    rk,rkd=a4(key,sb,rc)
    W=a5(ib)
    prev=iv
    out=bytearray()
    n=len(ct)&~15
    for i in range(0,n,16):
        c=ct[i:i+16]
        d=a7(c,rkd,W,ib)
        o=bytearray(16)
        for j in range(16):
            o[j]=d[j]^prev[j]
        out+=o
        prev=c
    return bytes(out)
def a9(buf):
    n=buf[-1]
    if not (1<=n<=16) or buf[-n:]!=bytes([n])*n:
        raise ValueError
    return buf[:-n]
def b1(so):
    sx,ix=so.find(SBOX_H),so.find(ISBOX_H)
    if sx<0 or ix<0:
        return None
    sb,ib=so[sx:sx+256],so[ix:ix+256]
    if len(sb)<256 or len(ib)<256 or not all(ib[sb[i]]==i for i in range(256)):
        return None
    rc=RCON_H
    r0=so.find(RCON_H)
    if r0>=0 and r0+10<=len(so):
        rc=bytes(so[r0:r0+10])
    return sb,ib,rc
def b2(so,limit=1100):
    c=re.findall(rb'[A-Za-z0-9]{16}',so)
    if not c:
        c=re.findall(rb'[\x20-\x7e]{16}',so)
    cnt={}
    for x in c:
        cnt[x]=cnt.get(x,0)+1
    def sc(it):
        k,n=it
        return (n,min(1,sum(65<=b<=90 for b in k))+min(1,sum(97<=b<=122 for b in k))+min(1,sum(48<=b<=57 for b in k)),len(set(k)))
    return sorted(cnt.items(),key=sc,reverse=True)[:limit]
def b3(so_blobs,sample,tbl,aenc_blob=None):
    sb,ib,rc=tbl
    allc=[]
    for so in so_blobs:
        allc+=b2(so)
    seen=set()
    cands=[]
    for c,_ in allc:
        if c not in seen:
            seen.add(c)
            cands.append(c)
    if len(cands)<2 or len(sample)<528:
        return None,None
    def app_ok(appb):
        if not appb or len(appb)<2:
            return False
        try:
            s=appb.decode('utf-8')
        except Exception:
            return False
        return bool(s) and not any(ord(x)<0x20 for x in s)
    def quick_check(k,iv):
        try:
            rk,rkd=a4(k,sb,rc)
            W=a5(ib)
            pt=bytearray()
            prev=iv
            for bi in range(5):
                ct=sample[bi*16:(bi+1)*16]
                d=a7(ct,rkd,W,ib)
                for j in range(16):
                    pt.append(d[j]^prev[j])
                prev=ct
            L=pt[0]
            if not (1<=L<=60) or not app_ok(bytes(pt[1:1+L])):
                return False
            pos=1+L
            if pos+8>len(pt):
                return False
            sz=struct.unpack('>I',pt[pos:pos+4])[0]
            return 4<=sz<=len(sample) and pt[pos+4:pos+8]==b'dex\n'
        except Exception:
            return False
    def final_check(k,iv):
        try:
            full=a8(sample[:528],k,iv,sb,ib,rc)
            full=a9(full)
        except Exception:
            return None
        payload=full+sample[528:]
        L=payload[0]
        if not (1<=L<=60) or not app_ok(payload[1:1+L]):
            return None
        pos=1+L
        if pos+4>len(payload):
            return None
        sz=struct.unpack('>I',payload[pos:pos+4])[0]
        if sz<=0 or pos+4+sz>len(payload):
            return None
        return payload if payload[pos+4:pos+8]==b'dex\n' else None
    def try_aenc(cset):
        if not (aenc_blob and aenc_blob[:4]==b'AENC' and len(aenc_blob)>=528):
            return None
        ad=aenc_blob[20:]
        an=len(ad)&~15
        if an<32:
            return None
        kh=[]
        for k in cset:
            try:
                rk,rkd=a4(k,sb,rc)
                W=a5(ib)
                t1=bytes(a^b for a,b in zip(a7(ad[an-16:an],rkd,W,ib),ad[an-32:an-16]))
                if 1<=t1[-1]<=16:
                    kh.append((k,t1[-1]))
            except Exception:
                continue
        kh2=[]
        for k,p in kh:
            try:
                rk,rkd=a4(k,sb,rc)
                W=a5(ib)
                blk=ad[an-64:an]
                pt=bytearray()
                prev=ad[an-80:an-64]
                for i in range(0,64,16):
                    d=a7(blk[i:i+16],rkd,W,ib)
                    for j in range(16):
                        pt.append(d[j]^prev[j])
                    prev=blk[i:i+16]
                if bytes([p])*p==pt[-p:]:
                    kh2.append(k)
            except Exception:
                continue
        for k in kh2:
            rkd=a4(k,sb,rc)[1]
            W=a5(ib)
            d0=a7(sample[:16],rkd,W,ib)
            for iv in cset:
                pt0=bytes(a^b for a,b in zip(d0,iv))
                L=pt0[0]
                if 1<=L<=60 and app_ok(pt0[1:1+min(L,15)]):
                    if quick_check(k,iv):
                        return k,iv
        return None
    def xor_scan(cset,strict):
        ct0=sample[:16]
        d0map={}
        for k in cset:
            try:
                rkd=a4(k,sb,rc)[1]
                d0map[k]=a7(ct0,rkd,a5(ib),ib)
            except Exception:
                pass
        iv_ints=[(iv,int.from_bytes(iv,'big')) for iv in cset]
        hr={}
        for k,dec0 in d0map.items():
            di=int.from_bytes(dec0,'big')
            for iv,ivi in iv_ints:
                pti=di^ivi
                L=(pti>>120)&0xff
                if strict:
                    if not (5<=L<=60):
                        continue
                    if not (0x41<=((pti>>112)&0xff)<=0x7a):
                        continue
                else:
                    if not (1<=L<=60):
                        continue
                    b1v=(pti>>112)&0xff
                    if not ((0x20<=b1v<=0x7e) or (b1v>=0x80)):
                        continue
                nl=L if L<15 else 15
                ok=True
                bad=0
                j=1
                while j<nl:
                    b=(pti>>(8*(15-j)))&0xff
                    if 0x20<=b<=0x7e:
                        j+=1
                    elif 0xc2<=b<=0xf4:
                        need=1 if b<=0xdf else (2 if b<=0xef else 3)
                        if j+need>=nl:
                            break
                        if all(0x80<=((pti>>(8*(15-(j+1+t))))&0xff)<=0xbf for t in range(need)):
                            j+=need+1
                            continue
                        ok=False
                        break
                    else:
                        if strict or nl-j<=2:
                            ok=False
                            break
                        bad+=1
                        j+=1
                        if bad>2:
                            ok=False
                            break
                if ok:
                    hr.setdefault(k,[]).append(iv)
        for k in sorted(hr,key=lambda x:-len(hr[x])):
            for iv in hr[k]:
                if quick_check(k,iv):
                    if final_check(k,iv):
                        return k,iv
        return None
    r=try_aenc(cands)
    if r:
        return r
    r=xor_scan(cands,True)
    if r:
        return r
    r=xor_scan(cands,False)
    if r:
        return r
    wide=list(set(re.findall(rb'[\x20-\x7e]{16}',b''.join(so_blobs))))
    wide=[c for c in wide if c not in seen][:4000]
    if wide:
        r=xor_scan(cands+wide,False)
        if r:
            return r
    return None,None
def b4(dex):
    if len(dex)<552:
        return None
    off=struct.unpack('>I',dex[-4:])[0]
    return off if 0x20<off<len(dex)-528 else None
def b5(dex,key,iv,tbl):
    off=b4(dex)
    if off is None:
        return None
    raw=dex[off:len(dex)-4]
    if len(raw)<528:
        return None
    try:
        head=a9(a8(raw[:528],key,iv,*tbl))
    except Exception:
        return None
    return head+raw[528:]
def b6(payload):
    if not payload or not (1<=payload[0]<=60):
        return None
    L=payload[0]
    app=payload[1:1+L]
    try:
        s=app.decode('utf-8')
    except Exception:
        return None
    if not s or any(ord(x)<0x20 for x in s):
        return None
    pos=1+L
    dexes=[]
    idx=0
    while pos+4<=len(payload):
        size=struct.unpack('>I',payload[pos:pos+4])[0]
        pos+=4
        if size<=0 or pos+size>len(payload):
            break
        d=bytearray(payload[pos:pos+size])
        if idx!=0:
            for i in range(min(112,len(d))):
                d[i]^=0x66
        dexes.append(bytes(d))
        pos+=size
        idx+=1
    return (app,dexes) if dexes else None
def b7(buf,fs):
    struct.pack_into('<I',buf,0x20,fs)
    buf[0x0C:0x20]=hashlib.sha1(bytes(buf[32:fs])).digest()
    struct.pack_into('<I',buf,0x08,zlib.adler32(bytes(buf[12:fs]))&0xFFFFFFFF)
    return buf
def b8(buf,key,sb,ib,rc):
    if buf[:4]!=b'AENC' or len(buf)<24 or key is None:
        return None
    data=buf[20:]
    n=len(data)&~15
    if n==0:
        return None
    pt=a8(data[:n],key,buf[4:20],sb,ib,rc)
    if len(data)>n:
        pt=pt+data[n:]
    pad=pt[-1]
    return bytes(pt[:-pad]) if 1<=pad<=16 and pad<=len(pt) else bytes(pt)
def b9(shell,enc,key,iv,tbl):
    sb,ib,rc=tbl
    dec=a8(shell[enc:enc+0x200],key,iv,sb,ib,rc)
    mp=dec.find(b'dex\n035\x00')
    if mp<0:
        return None
    hdr=dec[mp:mp+0x70]
    fs=struct.unpack_from('<I',hdr,0x20)[0]
    if not (0x100<=fs<=0x400000):
        return None
    sidc,sido=struct.unpack_from('<II',hdr,0x38)
    tic,tio=struct.unpack_from('<II',hdr,0x40)
    prc,pro=struct.unpack_from('<II',hdr,0x48)
    fdc,fdo=struct.unpack_from('<II',hdr,0x50)
    mec,meo=struct.unpack_from('<II',hdr,0x58)
    clc,clo=struct.unpack_from('<II',hdr,0x60)
    da0=struct.unpack_from('<I',hdr,0x6c)[0]
    base=enc+0x2C
    n_plain=sidc-93
    nd=bytearray(fs)
    nd[0:0x70]=hdr
    nd[sido:sido+93*4]=dec[mp+sido:mp+sido+93*4]
    nd[sido+93*4:sido+sidc*4]=shell[enc+0x210:enc+0x210+n_plain*4]
    for off,cnt,sz in ((tio,tic,4),(pro,prc,12),(fdo,fdc,8),(meo,mec,8),(clo,clc,32)):
        nd[off:off+cnt*sz]=shell[base+off:base+off+cnt*sz]
    nd[da0:fs]=shell[base+da0:base+fs]
    return b7(nd,fs)
def c1(shell):
    m=bytes([0x02,0x03,0x1e,0x6c,0x56,0x55,0x53,0x66])
    out,start=[],0
    while True:
        i=shell.find(m,start)
        if i<0:
            break
        T=i-4
        src=shell[T:T+0x80000]
        if len(src)<0x80:
            break
        md0=bytes(b^0x66 for b in src[0x004:0x074])
        if md0[:4]!=b'dex\n':
            start=i+8
            continue
        fs=struct.unpack_from('<I',md0,0x20)[0]
        if not (0x100<=fs<=0x80000):
            start=i+8
            continue
        md=bytearray(fs)
        md[0:0x70]=md0
        md[0x70:fs]=src[0x074:0x074+fs-0x70]
        out.append((T,fs,bytes(b7(md,fs))))
        start=i+fs
    return out
x7={
    '检测VPN':(b'getActiveNetwork',b'NetworkCapabilities'),
    '检测Root':('发现root上下文',b'SELinux permissive',b'which su',b'/data/adb/magisk',b'getenforce',b'tcontext=u:r:su:s0'),
    '检测虚拟机':(b'cat /proc/cmdline',b'cat /proc/version',b'ro.kernel.qemu',b'ranchu'),
    '检测Hook':(b'Xposed',b'frida',b'hook detect',b'hookDetect',b'Zygisk',b'Riru'),
    '签名校验(Shell)':(b'CheckSignature',b'checkSign',b'verifySignature',b'signature verify'),
    '签名校验(Svc)':(b'CheckSignature',b'checkSign',b'verifySignature',b'signature verify'),
    '断网检测':(b'getNetworkCapabilities',b'getActiveNetwork','网络检测线程','后台检测线程已启动'),
    'Assets资源内容加密':(b'AssetHooker',),
}
def c2(so_blob,names,z):
    res={}
    for label,pats in x7.items():
        on=any((p.encode() if isinstance(p,str) else p) in so_blob for p in pats)
        if label=='Assets资源内容加密':
            on=on or any(z.read(n)[:4]==b'AENC' for n in names if n.startswith('assets/') and not n.endswith('.so'))
        res[label]=on
    return res
def c3(data):
    L=len(data)
    u16=lambda o:struct.unpack_from('<H',data,o)[0]
    u32=lambda o:struct.unpack_from('<I',data,o)[0]
    pos,strings=8,[]
    while pos+8<=L:
        t,sz=u16(pos),u32(pos+4)
        if t==0x0001:
            sc,fl,ss=u32(pos+8),u32(pos+16),u32(pos+20)
            utf8=bool(fl&0x100)
            for i in range(min(sc,8000)):
                p=pos+ss+u32(pos+28+i*4)
                if p>=L:
                    continue
                if utf8:
                    b0=data[p];p+=1
                    if b0&0x80:p+=1
                    b1=data[p];p+=1
                    if b1&0x80:p+=1
                    strings.append(data[p:p+b1].decode('utf-8','ignore'))
                else:
                    ln=u16(p)
                    strings.append(data[p+2:p+2+min(ln*2,L-p-2)].decode('utf-16-le','ignore'))
            pos+=sz
        elif t==0x0102:
            nm=u32(pos+20);ac=u16(pos+28);astart=u16(pos+24)
            if nm<len(strings) and strings[nm]=='application':
                ab=pos+16+astart
                for i in range(ac):
                    q=ab+i*20
                    if q+20>L:
                        break
                    if strings[u32(q+4)]=='name':
                        raw=u32(q+8)
                        strings.append('__APP_NAME__:'+(strings[raw] if raw<len(strings) else '')+':')
                        return strings
            pos+=sz
        else:
            pos+=sz if sz>=8 else 8
    return strings
def c4(apk):
    try:
        ss=c3(zipfile.ZipFile(apk).read('AndroidManifest.xml'))
    except Exception:
        return 'unknown.pkg',None
    app=None
    for s in ss:
        if s.startswith('__APP_NAME__:'):
            app=s.split(':',1)[1][:-1]
    cand,seg=None,99
    for s in ss:
        s2=s.rstrip('\x00')
        if re.match(r'^[A-Za-z][A-Za-z0-9_]*\.[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$',s2):
            if s2.startswith(('android.','com.android','com.tosks')):
                continue
            n=s2.count('.')
            if n<seg:
                seg,cand=n,s2
    return cand or 'unknown.pkg',app
def c5():
    apk=(' '.join(sys.argv[1:]) if len(sys.argv)>=2 else input('请输入 APK 路径: ')).strip().strip('"').strip("'")
    if not os.path.isfile(apk):
        print('文件不存在')
        return
    z=zipfile.ZipFile(apk)
    names=z.namelist()
    tosks_sos=[n for n in names if '/libtosks' in n and n.endswith('.so')]
    if not tosks_sos and 'com.tosks' not in '\n'.join(names):
        print('未识别到 tosks 加固')
        return
    pkg,_mn=c4(apk)
    so_blobs={n:z.read(n) for n in tosks_sos}
    blob_all=b''.join(so_blobs.values())
    tbl=None
    for so in so_blobs.values():
        tbl=b1(so)
        if tbl:
            break
    if tbl is None:
        print('[!] 无法提取 SBOX, 中止')
        return
    aenc_probe=None
    for n in names:
        if n.startswith('assets/') and not n.endswith('.so'):
            d=z.read(n)
            if d[:4]==b'AENC' and len(d)>=528:
                aenc_probe=d
                break
    kv=(None,None)
    if 'classes.dex' in names:
        shx=z.read('classes.dex')
        off=b4(shx)
        if off:
            sample=shx[off:len(shx)-4]
            kv=b3(list(so_blobs.values()),sample,tbl,aenc_blob=aenc_probe)
    feats=c2(blob_all,names,z)
    baseout='/storage/emulated/0/tosks还原'
    try:
        pkgdir=os.path.join(baseout,pkg)
        dexdir=os.path.join(pkgdir,'静态脱壳')
        outdir=os.path.join(pkgdir,'Assets资源内容加密还原','assets')
        os.makedirs(dexdir,exist_ok=True)
        os.makedirs(outdir,exist_ok=True)
    except Exception:
        bd=os.path.dirname(os.path.abspath(apk))
        pkgdir=os.path.join(bd,pkg)
        dexdir=os.path.join(pkgdir,'静态脱壳')
        outdir=os.path.join(pkgdir,'Assets资源内容加密还原','assets')
        os.makedirs(dexdir,exist_ok=True)
        os.makedirs(outdir,exist_ok=True)
    ok=fail=0
    saved=[]
    aenc_key=kv[0]
    for n in names:
        if not n.startswith('assets/') or n.endswith('.so'):
            continue
        d=z.read(n)
        rel=n[len('assets/'):]
        name=''.join(ch if (ch.isprintable() and not ch.isspace()) else '_' for ch in rel.split('/')[-1]) or 'asset_%03d'%ok
        dst=os.path.join(outdir.rstrip('/'),name)
        if os.path.exists(dst):
            dst=os.path.join(outdir.rstrip('/'),'%03d_%s'%(ok,name))
        if d[:4]==b'AENC':
            if not aenc_key:
                print('解密失败(无key):',n)
                fail+=1
                continue
            dec=b8(d,aenc_key,*tbl)
            if dec is None:
                print('解密失败:',n)
                fail+=1
                continue
            d=dec
        open(dst,'wb').write(d)
        saved.append(rel)
        ok+=1
    restored=[]
    parsed=None
    if 'classes.dex' in names:
        shell=z.read('classes.dex')
        if kv[0]:
            payload=b5(shell,kv[0],kv[1],tbl)
            parsed=b6(payload) if payload else None
        if parsed:
            app_payload,dexes=parsed
            for i,d in enumerate(dexes):
                restored.append(('classes.dex' if i==0 else 'classes%d.dex'%(i+1),d))
        else:
            moff=struct.unpack_from('<I',shell,0x34)[0]
            enc=moff+4+struct.unpack_from('<I',shell,moff)[0]*12
            k2,iv2=kv
            if k2 is None:
                cands_all=[]
                for so in so_blobs.values():
                    cands_all+=[c for c,_ in b2(so)]
                cands_all=sorted(set(cands_all))[:400]
                ct0=shell[enc:enc+16]
                d0map={}
                Wm=a5(tbl[1])
                for k in cands_all:
                    try:
                        rkd=a4(k,tbl[0],tbl[2])[1]
                        d0map[k]=a7(ct0,rkd,Wm,tbl[1])
                    except Exception:
                        pass
                iv_int=[(iv,int.from_bytes(iv,'big')) for iv in cands_all]
                for k,dec0 in d0map.items():
                    di=int.from_bytes(dec0,'big')
                    for iv,ivi in iv_int[:200]:
                        pti=di^ivi
                        L=(pti>>120)&0xff
                        if not (1<=L<=60):
                            continue
                        try:
                            dec=a8(shell[enc:enc+0x210],k,iv,tbl[0],tbl[1],tbl[2])
                            if dec.find(b'dex\n035\x00')>=0:
                                k2,iv2=k,iv
                                break
                        except Exception:
                            pass
                    if k2:
                        break
            if k2:
                r=b9(shell,enc,k2,iv2,tbl)
                if r:
                    restored.append(('classes.dex',r))
                for kk,(_T,_fs,md) in enumerate(c1(shell)):
                    restored.append(('classes%d.dex'%(kk+2),md))
    for fn,d in restored:
        try:
            fs=struct.unpack_from('<I',d,0x20)[0]
            if d[:4]==b'dex\n' and fs==len(d):
                d=bytes(b7(bytearray(d),fs))
        except Exception:
            pass
        open(os.path.join(dexdir,fn),'wb').write(d)
    entry=parsed[0].decode('utf-8','ignore') if parsed else 'android.app.Application'
    lines=['源文件: %s'%os.path.basename(apk),
           '包名:%s'%pkg,
           '原始入口:%s'%entry]
    fl=['/%s'%fn for fn,_ in restored]+['/assets/'+rel for rel in saved]
    lines.append('还原文件: 共%d个'%len(fl))
    lines.append('资源列表:')
    lines+=fl
    lines.append('tosks功能开关')
    lines+=['[%s]%s'%('√' if on else '×',label) for label,on in feats.items()]
    with open(os.path.join(dexdir,'说明.txt'),'w',encoding='utf-8') as f:
        f.write('\n'.join(lines)+'\n')
    print()
    print('\n'.join(lines))
if __name__=='__main__':
    c5()