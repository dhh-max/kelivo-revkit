#!/usr/bin/env python3
"""多语言国际化 (i18n) 支持 - 7种语言

支持语言:
  zh_CN - 简体中文 (默认)
  en    - English (英语)
  ja    - 日本語 (日语)
  ko    - 한국어 (韩语)
  ru    - Русский (俄语)
  zh_TW - 繁體中文 (繁体)
  hi    - हिन्दी (印地语)

用法:
  from apk_reverse_engine.utils.i18n import _
  print(_("分析完成"))  # 根据当前语言设置输出翻译
"""

import os, json

# ── 当前语言设置 ──────────────────────────────────────────
_current_lang = os.environ.get("RENG_LANG", "zh_CN")
_lang_file = None  # 持久化存储路径

def set_lang_file(path):
    """设置语言持久化存储文件路径"""
    global _lang_file
    _lang_file = path

def get_saved_lang():
    """读取持久化语言设置"""
    if _lang_file and os.path.exists(_lang_file):
        try:
            with open(_lang_file, 'r', encoding='utf-8') as f:
                return json.load(f).get("lang", "zh_CN")
        except Exception as e:
            from apk_reverse_engine.utils.logutil import get_logger; get_logger(__name__).debug("apk_reverse_engine/utils/i18n.py:35 suppressed: %s", e)
            pass
    return os.environ.get("RENG_LANG", "zh_CN")

def save_lang(lang):
    """持久化保存语言设置"""
    global _current_lang
    _current_lang = lang
    if _lang_file:
        try:
            os.makedirs(os.path.dirname(_lang_file), exist_ok=True)
            with open(_lang_file, 'w', encoding='utf-8') as f:
                json.dump({"lang": lang}, f, ensure_ascii=False)
            return True
        except Exception as e:
            from apk_reverse_engine.utils.logutil import get_logger
            get_logger(__name__).warning("save_lang failed: %s", e)
            return False
    return False

# ── 语言列表 ──────────────────────────────────────────────
LANGUAGES = {
    "zh_CN": "简体中文",
    "en":    "English",
    "ja":    "日本語",
    "ko":    "한국어",
    "ru":    "Русский",
    "zh_TW": "繁體中文",
    "hi":    "हिन्दी",
}

LANG_CODES = list(LANGUAGES.keys())

def set_lang(lang):
    """设置当前语言"""
    global _current_lang
    if lang in LANGUAGES:
        _current_lang = lang
        return True
    return False

def get_lang():
    return _current_lang

# ── 翻译字典 ──────────────────────────────────────────────
# 格式: { "zh_CN原文": {"en": "...", "ja": "...", ...} }
# 未翻译的语言自动回退到 zh_CN
_TRANSLATIONS = {}

def _t(key, lang=None):
    """翻译单个 key"""
    if lang is None:
        lang = _current_lang
    if lang == "zh_CN":
        return key
    entry = _TRANSLATIONS.get(key)
    if entry and lang in entry:
        return entry[lang]
    return key  # 回退到中文

# ── 主翻译函数 ────────────────────────────────────────────
def _(text, *args, **kwargs):
    """翻译文本，支持 %s 格式化

    Args:
        text: 要翻译的文本（中文原文）
        *args: 位置格式化参数
        **kwargs: 命名格式化参数

    Returns:
        翻译后的文本
    """
    lang = kwargs.pop('_lang', None) or _current_lang
    translated = _t(text, lang)
    if args or kwargs:
        try:
            return translated % args if args else translated % kwargs
        except Exception:
            return translated
    return translated

# ── 注册翻译条目 ──────────────────────────────────────────
def register(translations):
    """批量注册翻译条目

    Args:
        translations: dict { "zh_CN原文": {"en": "...", "ja": "...", ...} }
    """
    _TRANSLATIONS.update(translations)

# ============================================================
# 通用翻译词条
# ============================================================
register({
    # ── 通用 ──
    "成功": {
        "en": "Success",
        "ja": "成功",
        "ko": "성공",
        "ru": "Успех",
        "zh_TW": "成功",
        "hi": "सफलता",
    },
    "失败": {
        "en": "Failed",
        "ja": "失敗",
        "ko": "실패",
        "ru": "Ошибка",
        "zh_TW": "失敗",
        "hi": "विफल",
    },
    "错误": {
        "en": "Error",
        "ja": "エラー",
        "ko": "오류",
        "ru": "Ошибка",
        "zh_TW": "錯誤",
        "hi": "त्रुटि",
    },
    "警告": {
        "en": "Warning",
        "ja": "警告",
        "ko": "경고",
        "ru": "Предупреждение",
        "zh_TW": "警告",
        "hi": "चेतावनी",
    },
    "信息": {
        "en": "Info",
        "ja": "情報",
        "ko": "정보",
        "ru": "Информация",
        "zh_TW": "資訊",
        "hi": "जानकारी",
    },
    "分析中...": {
        "en": "Analyzing...",
        "ja": "分析中...",
        "ko": "분석 중...",
        "ru": "Анализ...",
        "zh_TW": "分析中...",
        "hi": "विश्लेषण हो रहा है...",
    },
    "完成": {
        "en": "Done",
        "ja": "完了",
        "ko": "완료",
        "ru": "Готово",
        "zh_TW": "完成",
        "hi": "पूर्ण",
    },

    # ── APK 分析 ──
    "APK 概览": {
        "en": "APK Overview",
        "ja": "APK概要",
        "ko": "APK 개요",
        "ru": "Обзор APK",
        "zh_TW": "APK概覽",
        "hi": "APK अवलोकन",
    },
    "包名": {
        "en": "Package",
        "ja": "パッケージ名",
        "ko": "패키지명",
        "ru": "Пакет",
        "zh_TW": "包名",
        "hi": "पैकेज",
    },
    "版本": {
        "en": "Version",
        "ja": "バージョン",
        "ko": "버전",
        "ru": "Версия",
        "zh_TW": "版本",
        "hi": "संस्करण",
    },
    "文件大小": {
        "en": "File Size",
        "ja": "ファイルサイズ",
        "ko": "파일 크기",
        "ru": "Размер файла",
        "zh_TW": "檔案大小",
        "hi": "फ़ाइल आकार",
    },
    "安全评分": {
        "en": "Security Score",
        "ja": "セキュリティスコア",
        "ko": "보안 점수",
        "ru": "Оценка безопасности",
        "zh_TW": "安全評分",
        "hi": "सुरक्षा स्कोर",
    },
    "权限": {
        "en": "Permissions",
        "ja": "権限",
        "ko": "권한",
        "ru": "Разрешения",
        "zh_TW": "權限",
        "hi": "अनुमतियाँ",
    },
    "签名": {
        "en": "Signature",
        "ja": "署名",
        "ko": "서명",
        "ru": "Подпись",
        "zh_TW": "簽名",
        "hi": "हस्ताक्षर",
    },
    "DEX 文件": {
        "en": "DEX Files",
        "ja": "DEXファイル",
        "ko": "DEX 파일",
        "ru": "DEX файлы",
        "zh_TW": "DEX檔案",
        "hi": "DEX फ़ाइलें",
    },
    "混淆检测": {
        "en": "Obfuscation Detection",
        "ja": "難読化検出",
        "ko": "난독화 탐지",
        "ru": "Обнаружение обфускации",
        "zh_TW": "混淆檢測",
        "hi": "अस्पष्टता पहचान",
    },
    "加固检测": {
        "en": "Packer Detection",
        "ja": "梱包検出",
        "ko": "패커 탐지",
        "ru": "Обнаружение упаковщика",
        "zh_TW": "加固檢測",
        "hi": "पैकर पहचान",
    },
    "未检测到加固壳": {
        "en": "No packer detected",
        "ja": "梱包は検出されませんでした",
        "ko": "패커가 감지되지 않았습니다",
        "ru": "Упаковщик не обнаружен",
        "zh_TW": "未檢測到加固殼",
        "hi": "कोई पैकर नहीं मिला",
    },
    "低风险": {
        "en": "Low Risk",
        "ja": "低リスク",
        "ko": "저위험",
        "ru": "Низкий риск",
        "zh_TW": "低風險",
        "hi": "कम जोखिम",
    },
    "中等": {
        "en": "Medium",
        "ja": "中程度",
        "ko": "중간",
        "ru": "Средний",
        "zh_TW": "中等",
        "hi": "मध्यम",
    },
    "严重": {
        "en": "Critical",
        "ja": "重大",
        "ko": "심각",
        "ru": "Критический",
        "zh_TW": "嚴重",
        "hi": "गंभीर",
    },

    # ── 命令相关 ──
    "可用命令:": {
        "en": "Available Commands:",
        "ja": "使用可能なコマンド:",
        "ko": "사용 가능한 명령:",
        "ru": "Доступные команды:",
        "zh_TW": "可用命令:",
        "hi": "उपलब्ध कमांड:",
    },
    "使用详情": {
        "en": "Usage",
        "ja": "使い方",
        "ko": "사용법",
        "ru": "Использование",
        "zh_TW": "使用詳情",
        "hi": "उपयोग",
    },
    "当前语言": {
        "en": "Current Language",
        "ja": "現在の言語",
        "ko": "현재 언어",
        "ru": "Текущий язык",
        "zh_TW": "當前語言",
        "hi": "वर्तमान भाषा",
    },
    "支持的语言": {
        "en": "Supported Languages",
        "ja": "対応言語",
        "ko": "지원 언어",
        "ru": "Поддерживаемые языки",
        "zh_TW": "支援的語言",
        "hi": "समर्थित भाषाएँ",
    },

    # ── 操作 ──
    "解包成功": {
        "en": "Decode successful",
        "ja": "デコード成功",
        "ko": "디코딩 성공",
        "ru": "Декодирование успешно",
        "zh_TW": "解包成功",
        "hi": "डिकोड सफल",
    },
    "重打包成功": {
        "en": "Build successful",
        "ja": "ビルド成功",
        "ko": "빌드 성공",
        "ru": "Сборка успешна",
        "zh_TW": "重打包成功",
        "hi": "बिल्ड सफल",
    },
    "签名成功": {
        "en": "Sign successful",
        "ja": "署名成功",
        "ko": "서명 성공",
        "ru": "Подпись успешна",
        "zh_TW": "簽名成功",
        "hi": "हस्ताक्षर सफल",
    },
    "反编译成功": {
        "en": "Decompile successful",
        "ja": "逆コンパイル成功",
        "ko": "역컴파일 성공",
        "ru": "Декомпиляция успешна",
        "zh_TW": "反編譯成功",
        "hi": "डीकंपाइल सफल",
    },
    "解压成功": {
        "en": "Unpack successful",
        "ja": "解凍成功",
        "ko": "압축 풀기 성공",
        "ru": "Распаковка успешна",
        "zh_TW": "解壓成功",
        "hi": "अनपैक सफल",
    },
    "补丁成功": {
        "en": "Patch successful",
        "ja": "パッチ成功",
        "ko": "패치 성공",
        "ru": "Патч успешен",
        "zh_TW": "補丁成功",
        "hi": "पैच सफल",
    },
    "搜索中...": {
        "en": "Searching...",
        "ja": "検索中...",
        "ko": "검색 중...",
        "ru": "Поиск...",
        "zh_TW": "搜索中...",
        "hi": "खोज हो रही है...",
    },
    "未找到匹配结果": {
        "en": "No results found",
        "ja": "結果が見つかりませんでした",
        "ko": "결과를 찾을 수 없습니다",
        "ru": "Результатов не найдено",
        "zh_TW": "未找到匹配結果",
        "hi": "कोई परिणाम नहीं मिला",
    },
    "找到匹配结果": {
        "en": "Results found",
        "ja": "結果が見つかりました",
        "ko": "결과를 찾았습니다",
        "ru": "Результаты найдены",
        "zh_TW": "找到匹配結果",
        "hi": "परिणाम मिले",
    },

    # ── 资源语言 ──
    "APK 资源语言": {
        "en": "APK Resource Languages",
        "ja": "APKリソース言語",
        "ko": "APK 리소스 언어",
        "ru": "Языки ресурсов APK",
        "zh_TW": "APK資源語言",
        "hi": "APK संसाधन भाषाएँ",
    },
    "语言列表": {
        "en": "Language List",
        "ja": "言語一覧",
        "ko": "언어 목록",
        "ru": "Список языков",
        "zh_TW": "語言列表",
        "hi": "भाषा सूची",
    },
    "提取字符串": {
        "en": "Extract Strings",
        "ja": "文字列抽出",
        "ko": "문자열 추출",
        "ru": "Извлечение строк",
        "zh_TW": "提取字串",
        "hi": "स्ट्रिंग निकालें",
    },
    "替换字符串": {
        "en": "Replace Strings",
        "ja": "文字列置換",
        "ko": "문자열 교체",
        "ru": "Замена строк",
        "zh_TW": "替換字串",
        "hi": "स्ट्रिंग बदलें",
    },
    "总字符串数": {
        "en": "Total Strings",
        "ja": "総文字列数",
        "ko": "총 문자열 수",
        "ru": "Всего строк",
        "zh_TW": "總字串數",
        "hi": "कुल स्ट्रिंग्स",
    },
    "已翻译": {
        "en": "Translated",
        "ja": "翻訳済み",
        "ko": "번역됨",
        "ru": "Переведено",
        "zh_TW": "已翻譯",
        "hi": "अनुवादित",
    },
    "未翻译": {
        "en": "Untranslated",
        "ja": "未翻訳",
        "ko": "미번역",
        "ru": "Не переведено",
        "zh_TW": "未翻譯",
        "hi": "अननुवादित",
    },
    "语言切换成功": {
        "en": "Language switched successfully",
        "ja": "言語を切り替えました",
        "ko": "언어가 전환되었습니다",
        "ru": "Язык успешно изменён",
        "zh_TW": "語言切換成功",
        "hi": "भाषा सफलतापूर्वक बदली गई",
    },
    "语言设置已保存": {
        "en": "Language setting saved",
        "ja": "言語設定を保存しました",
        "ko": "언어 설정이 저장되었습니다",
        "ru": "Настройка языка сохранена",
        "zh_TW": "語言設定已儲存",
        "hi": "भाषा सेटिंग सहेजी गई",
    },

    # ── 清理/优化 ──
    "APK 清理": {
        "en": "APK Cleanup",
        "ja": "APKクリーンアップ",
        "ko": "APK 정리",
        "ru": "Очистка APK",
        "zh_TW": "APK清理",
        "hi": "APK सफाई",
    },
    "移除的文件": {
        "en": "Removed Files",
        "ja": "削除されたファイル",
        "ko": "제거된 파일",
        "ru": "Удалённые файлы",
        "zh_TW": "移除的檔案",
        "hi": "हटाई गई फ़ाइलें",
    },
    "节省空间": {
        "en": "Space Saved",
        "ja": "節約された容量",
        "ko": "절약된 공간",
        "ru": "Сэкономлено",
        "zh_TW": "節省空間",
        "hi": "बचत स्थान",
    },
})

# ============================================================
# 便捷函数
# ============================================================
def ngettext(singular, plural, count):
    """复数形式翻译（简化版，仅英语区分单复数）"""
    if _current_lang == "en":
        return _(plural) if count != 1 else _(singular)
    return _(singular)  # 其他语言不区分

def language_name(code):
    """获取语言代码对应的显示名称"""
    return LANGUAGES.get(code, code)

# ============================================================
# 初始化：尝试加载持久化语言设置
# ============================================================
_config_dir = None
_home = os.path.expanduser("~")
for _d in [os.path.join(_home, ".config", "reng"),
           os.path.join(_home, ".reng")]:
    _f = os.path.join(_d, "lang.json")
    if os.path.exists(_f):
        try:
            with open(_f, 'r', encoding='utf-8') as _lf:
                _data = json.load(_lf)
                if _data.get("lang") in LANGUAGES:
                    _current_lang = _data["lang"]
                    _lang_file = _f
                    break
        except Exception as e:
            from apk_reverse_engine.utils.logutil import get_logger; get_logger(__name__).debug("apk_reverse_engine/utils/i18n.py:539 suppressed: %s", e)
            pass

# 如果没有找到持久化配置，设置默认路径
if _lang_file is None:
    _config_dir = os.path.join(_home, ".config", "reng")
    _lang_file = os.path.join(_config_dir, "lang.json")
    set_lang_file(_lang_file)