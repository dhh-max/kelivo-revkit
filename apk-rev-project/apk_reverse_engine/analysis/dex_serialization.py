"""DEX 序列化/数据持久化分析 — Serializable/Parcelable/序列化字段/数据泄露风险"""
from apk_reverse_engine.utils.logutil import get_logger
logger = get_logger(__name__)
from collections import Counter, defaultdict


class DexSerializationAnalyzer:
    """DEX 序列化与数据持久化分析 — 序列化接口/字段/栈溢出风险"""

    SERIAL_IFACES = [
        'Ljava/io/Serializable;', 'Landroid/os/Parcelable;',
        'Landroid/os/Parcel;', 'Ljava/io/ObjectOutputStream;',
        'Ljava/io/ObjectInputStream;', 'Ljava/io/Externalizable;',
    ]
    # 持久化相关
    PERSIST_PATTERNS = [
        'SharedPreferences', 'SQLiteDatabase', 'openOrCreateDatabase',
        'writeToParcel', 'readFromParcel', 'createFromParcel',
        'ObjectOutputStream', 'writeObject', 'readObject',
        'getSharedPreferences', 'filesDir', 'cacheDir',
    ]

    @staticmethod
    def analyze(dex_parser):
        """分析 DEX 序列化与数据持久化"""
        dex_parser._ensure_parsed()
        class_defs = dex_parser.get_class_defs()
        strings = dex_parser.get_strings()
        if not class_defs:
            return {'error': '无类定义数据'}
        serializable_classes = []
        parcelable_classes = []
        persist_hits = Counter()
        total_classes = len(class_defs)
        # 检查类实现的接口
        for cd in class_defs:
            cn = cd.get('class_name', '')
            ifaces = cd.get('interfaces') or []
            super_name = cd.get('super_name', '')
            if any('Serializable' in i.split('/')[-1] or 'Serializable' in i for i in ifaces):
                serializable_classes.append(cn)
            if any('Parcelable' in i.split('/')[-1] or 'Parcelable' in i for i in ifaces):
                parcelable_classes.append(cn)
        # 字符串持久化特征
        for s in strings:
            if not s:
                continue
            for pat in DexSerializationAnalyzer.PERSIST_PATTERNS:
                if pat in s:
                    persist_hits[pat] += 1
        # 序列化风险评分 (大量自定义序列化数据可被篡改/reverse)
        serial_count = len(serializable_classes)
        parcel_count = len(parcelable_classes)
        persist_total = sum(persist_hits.values())
        risk_score = min(100, int(min(persist_total * 0.8, 50) + min(serial_count * 2, 25) + min(parcel_count * 2, 25)))
        if risk_score >= 60:
            risk_level = '高持久化'
        elif risk_score >= 30:
            risk_level = '中持久化'
        else:
            risk_level = '低持久化'
        return {
            'total_classes': total_classes,
            'serializable_class_count': serial_count,
            'parcelable_class_count': parcel_count,
            'serializable_classes': [c.replace('L', '').replace(';', '').replace('/', '.') for c in serializable_classes[:20]],
            'parcelable_classes': [c.replace('L', '').replace(';', '').replace('/', '.') for c in parcelable_classes[:20]],
            'persist_hits': [{'pattern': p, 'count': c} for p, c in persist_hits.most_common(15)],
            'persist_total': persist_total,
            'risk_score': risk_score,
            'risk_level': risk_level,
        }

    @staticmethod
    def get_summary(result):
        if 'error' in result:
            return result
        return {
            'serializable_class_count': result['serializable_class_count'],
            'parcelable_class_count': result['parcelable_class_count'],
            'persist_total': result['persist_total'],
            'risk_level': result['risk_level'],
            'top3_persist': result['persist_hits'][:3],
        }