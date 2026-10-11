"""DEX 类型引用分析 — 类型引用矩阵/高耦合枢纽类/依赖关系"""
from apk_reverse_engine.utils.logutil import get_logger
logger = get_logger(__name__)
from collections import defaultdict, Counter

class DexTypeRefAnalyzer:
    """DEX 类型引用深度分析 — 找出类型间依赖关系与枢纽类"""

    # 内置/系统类型前缀（排除，聚焦应用自有类）
    SYSTEM_PREFIXES = (
        'Ljava/', 'Landroid/', 'Lorg/', 'Lcom/google/', 'Lkotlin/',
        'Ljavax/', 'Ldalvik/', 'Lsun/', 'Llibcore/', 'Lkotlinx/',
        'Lokhttp3/', 'Lretrofit2/', 'Lio/reactivex/', 'Lrx/',
        'Lcom/squareup/', 'Landroidx/', 'Lbutterknife/', 'Ldagger/',
    )

    @staticmethod
    def _is_app_class(desc):
        """判断是否为应用自有类（非系统/SDK）"""
        if not desc or not desc.startswith('L'):
            return False
        return not desc.startswith(DexTypeRefAnalyzer.SYSTEM_PREFIXES)

    @staticmethod
    def analyze(dex_parser):
        """分析 DEX 类型引用关系"""
        dex_parser._ensure_parsed()
        class_defs = dex_parser.get_class_defs()
        fields = dex_parser.get_fields()
        methods = dex_parser.get_methods()
        types = dex_parser.get_types()

        # 类型 -> 描述符 映射
        type_descs = {}
        for t in types:
            if isinstance(t, dict):
                type_descs[t.get('id')] = t.get('descriptor', '')
            else:
                type_descs[len(type_descs)] = str(t)

        # 引用矩阵: referrer -> referenced
        ref_in = defaultdict(Counter)   # 被引用类型收到的引用
        ref_out = defaultdict(Counter)  # 引用类型发出的引用
        app_class_defined = set()

        # 1. 收集应用自有类
        for cd in class_defs:
            name = cd.get('class_name', '')
            if DexTypeRefAnalyzer._is_app_class(name):
                app_class_defined.add(name)

        # 2. 字段类型引用
        field_refs = 0
        for f in fields:
            if not isinstance(f, dict):
                continue
            cls = f.get('class_name', '')
            ftype = f.get('type', '')
            if not cls or not ftype:
                continue
            if DexTypeRefAnalyzer._is_app_class(ftype):
                ref_in[ftype][cls] += 1
                ref_out[cls][ftype] += 1
                field_refs += 1

        # 3. 方法签名引用 (参数 + 返回类型)
        method_refs = 0
        for m in methods:
            if not isinstance(m, dict):
                continue
            cls = m.get('class_name', '')
            proto = m.get('proto') or {}
            ret = proto.get('return_type', '') if isinstance(proto, dict) else ''
            if DexTypeRefAnalyzer._is_app_class(ret):
                ref_in[ret][cls] += 1
                ref_out[cls][ret] += 1
                method_refs += 1
            for p in (proto.get('parameters', []) if isinstance(proto, dict) else []):
                if DexTypeRefAnalyzer._is_app_class(p):
                    ref_in[p][cls] += 1
                    ref_out[cls][p] += 1
                    method_refs += 1

        # 4. 继承/接口引用
        inher_refs = 0
        for cd in class_defs:
            cls = cd.get('class_name', '')
            super_n = cd.get('super_name', '')
            if DexTypeRefAnalyzer._is_app_class(super_n):
                ref_in[super_n][cls] += 1
                ref_out[cls][super_n] += 1
                inher_refs += 1
            for itf in (cd.get('interfaces') or []):
                if DexTypeRefAnalyzer._is_app_class(itf):
                    ref_in[itf][cls] += 1
                    ref_out[cls][itf] += 1
                    inher_refs += 1

        # 5. 计算枢纽类评分 (被引用数 + 引用数)
        hub_scores = {}
        all_keys = set(ref_in.keys()) | set(ref_out.keys())
        for k in all_keys:
            in_cnt = sum(ref_in[k].values())
            out_cnt = sum(ref_out[k].values())
            hub_scores[k] = {
                'incoming': in_cnt,
                'outgoing': out_cnt,
                'total': in_cnt + out_cnt,
                'fan_in': len(ref_in[k]),
                'fan_out': len(ref_out[k]),
            }

        # 6. 依赖环检测 (简化 - 双向引用)
        bidirectional = []
        for a in list(ref_out.keys())[:800]:
            for b in ref_out[a]:
                if b in ref_out and a in ref_out[b]:
                    bidir = (a, b)
                    if (b, a) not in bidirectional:
                        bidirectional.append(bidir)

        # 类名格式化辅助
        def fmt(desc):
            return desc.replace('L', '').replace(';', '').replace('/', '.') if desc.startswith('L') else desc

        # 枢纽类排序
        hubs = sorted(
            [(fmt(k), v) for k, v in hub_scores.items() if k in app_class_defined],
            key=lambda x: x[1]['total'], reverse=True
        )

        # 统计
        total_app_classes = len(app_class_defined)
        total_refs = field_refs + method_refs + inher_refs

        return {
            'total_app_classes': total_app_classes,
            'total_field_refs': field_refs,
            'total_method_refs': method_refs,
            'total_inheritance_refs': inher_refs,
            'total_refs': total_refs,
            'hub_classes': [
                {'class': c, 'incoming': s['incoming'], 'outgoing': s['outgoing'],
                 'total': s['total'], 'fan_in': s['fan_in'], 'fan_out': s['fan_out']}
                for c, s in hubs[:30]
            ],
            'bidirectional_deps': [
                {'a': fmt(a), 'b': fmt(b)} for a, b in bidirectional[:30]
            ],
            'bidirectional_count': len(bidirectional),
            'top_incoming': [
                {'class': fmt(k), 'count': c} for k, c in
                sorted(((k, sum(v.values())) for k, v in ref_in.items()), key=lambda x: x[1], reverse=True)[:20]
            ],
            'top_outgoing': [
                {'class': fmt(k), 'count': c} for k, c in
                sorted(((k, sum(v.values())) for k, v in ref_out.items()), key=lambda x: x[1], reverse=True)[:20]
            ],
        }

    @staticmethod
    def get_summary(result):
        return {
            'app_classes': result['total_app_classes'],
            'total_refs': result['total_refs'],
            'field_refs': result['total_field_refs'],
            'method_refs': result['total_method_refs'],
            'inheritance_refs': result['total_inheritance_refs'],
            'bidirectional_deps': result['bidirectional_count'],
            'top5_hubs': result['hub_classes'][:5],
        }