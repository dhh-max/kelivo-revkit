#!/usr/bin/env python3
"""社交登录检测模块 - 识别APK中的微信/QQ/GitHub/支付宝等第三方登录集成

检测维度:
1. SDK特征: 识别各平台登录SDK（包名/类名前缀）
2. 代码模式: 检测登录相关API调用（授权/回调/Token）
3. 字符串特征: 登录平台AppID/回调URL/Scope等
4. 综合评分: 给出各平台集成密度评分
"""
import re
from collections import Counter, defaultdict


class SocialLoginDetector:
    """APK 社交登录检测器 - 识别微信/QQ/GitHub/支付宝等第三方登录"""

    # ── 平台 SDK 特征签名（包名/类名前缀） ──────────────────
    PLATFORM_SIGNATURES = {
        'wechat': {
            'name': '微信登录',
            'icon': '💬',
            'risk': '中',
            'patterns': [
                (r'com\.tencent\.mm\.opensdk', '微信OpenSDK'),
                (r'com\.tencent\.mm\.sdk', '微信SDK'),
                (r'com\.tencent\.connect', '腾讯互联(微信/QQ)'),
                (r'com\.tencent\.open\b', '腾讯开放平台'),
                (r'com\.tencent\.tauth', '腾讯TAuth'),
                (r'com\.tencent\.mm\.demo', '微信Demo'),
                (r'wx[a-z0-9]{16,}', '微信AppID模式'),
            ],
            'code_patterns': [
                r'WXEntryActivity', r'WXPayEntryActivity',
                r'WXApi', r'IWXAPI', r'sendReq', r'sendResp',
                r'wechat_auth', r'wechat_login', r'wx_login',
                r'wechat_token', r'wx_token', r'wechat_openid',
                r'wechat_unionid', r'wechat_refresh_token',
                r'wechat_user_info', r'wechat_nickname',
                r'wechat_headimgurl', r'wechat_sex',
                r'wechat_province', r'wechat_city',
                r'wechat_country', r'wechat_privilege',
                r'fromScene', r'WeChatLogin',
            ],
            'string_patterns': [
                r'wx[a-z0-9]{16,}',  # 微信AppID
                r'wechat', r'weixin', r'微信',
                r'openid', r'unionid',
                r'snsapi_userinfo', r'snsapi_base',
                r'wechat://',
                r'https://api\.weixin\.qq\.com',
                r'https://open\.weixin\.qq\.com',
            ],
            'url_patterns': [
                r'api\.weixin\.qq\.com',
                r'open\.weixin\.qq\.com',
                r'wechat\.com',
            ],
        },
        'qq': {
            'name': 'QQ登录',
            'icon': '🐧',
            'risk': '中',
            'patterns': [
                (r'com\.tencent\.connect', '腾讯互联(QQ/微信)'),
                (r'com\.tencent\.open', '腾讯开放平台'),
                (r'com\.tencent\.tauth', '腾讯TAuth'),
                (r'com\.tencent\.qq', 'QQSDK'),
                (r'com\.tencent\.mobileqq', '手机QQ'),
                (r'open_sdk', 'QQ开放SDK'),
                (r'mqqapi', 'QQ API'),
            ],
            'code_patterns': [
                r'Tencent', r'QQLogin', r'qq_login', r'qq_auth',
                r'QQToken', r'qq_token', r'qq_openid',
                r'qq_user_info', r'qq_nickname', r'qq_avatar',
                r'QQLoginListener', r'IUiListener',
                r'onComplete', r'onError', r'onCancel',
                r'QQAuth', r'mAuthIntent', r'getQQToken',
                r'qq_sso', r'qq_connect',
                r'com_tencent_tauth', r'TAuthActivity',
            ],
            'string_patterns': [
                r'tencent[0-9]{5,}',  # QQ AppID
                r'qq', r'QQ', r'tencent',
                r'get_user_info', r'get_simple_userinfo',
                r'get_info', r'get_app_friends',
                r'add_topic', r'add_share',
                r'mqqapi://', r'openmobile\.qq\.com',
                r'graph\.qq\.com',
                r'https://qz\.qq\.qq\.com',
            ],
            'url_patterns': [
                r'graph\.qq\.com',
                r'openmobile\.qq\.com',
                r'qz\.qq\.qq\.com',
                r'connect\.qq\.com',
            ],
        },
        'github': {
            'name': 'GitHub登录',
            'icon': '🐙',
            'risk': '低',
            'patterns': [
                (r'com\.github', 'GitHub SDK'),
                (r'org\.github', 'GitHub Org'),
                (r'io\.github', 'GitHub IO'),
                (r'github\.login', 'GitHub Login'),
                (r'github\.auth', 'GitHub Auth'),
                (r'github\.oauth', 'GitHub OAuth'),
            ],
            'code_patterns': [
                r'GitHubLogin', r'github_login', r'github_auth',
                r'GitHubToken', r'github_token',
                r'GitHubOAuth', r'github_oauth',
                r'GitHubCallback', r'github_callback',
                r'GitHubUser', r'github_user',
                r'GitHubRepo', r'github_repo',
                r'Octokit', r'octokit',
                r'GithubClient', r'github_client',
                r'GithubApi', r'github_api',
                r'GithubSdk', r'github_sdk',
                r'GitHubAuthActivity', r'GitHubLoginActivity',
            ],
            'string_patterns': [
                r'github\.com/login',
                r'github\.com/oauth',
                r'github\.com/login/oauth',
                r'api\.github\.com',
                r'github\.com/user',
                r'github\.com/users',
                r'github\.com/authorize',
                r'github\.com/access_token',
                r'client_id=[a-z0-9]+',
                r'client_secret=[a-z0-9]+',
                r'github_token', r'github_oauth',
                r'github_login', r'github_auth',
                r'ghp_[a-zA-Z0-9]{36,}',  # GitHub PAT
                r'gho_[a-z0-9]{36,}',     # GitHub OAuth
                r'ghu_[a-z0-9]{36,}',     # GitHub User
                r'ghs_[a-z0-9]{36,}',     # GitHub SSH
            ],
            'url_patterns': [
                r'github\.com',
                r'api\.github\.com',
                r'raw\.githubusercontent\.com',
                r'gist\.github\.com',
            ],
        },
        'alipay': {
            'name': '支付宝登录',
            'icon': '💳',
            'risk': '中',
            'patterns': [
                (r'com\.alipay\.sdk', '支付宝SDK'),
                (r'com\.alipay\.android', '支付宝Android'),
                (r'com\.alipay\.mobile', '支付宝移动端'),
                (r'com\.alipay\.auth', '支付宝Auth'),
                (r'com\.alipay\.pay', '支付宝支付'),
                (r'com\.alipay\.plus', '支付宝Plus'),
                (r'alipaySdk', '支付宝SDK'),
                (r'alipay\.android', '支付宝Android'),
                (r'alipaysec', '支付宝安全'),
            ],
            'code_patterns': [
                r'AlipayLogin', r'alipay_login', r'alipay_auth',
                r'AlipayToken', r'alipay_token',
                r'AlipayAuth', r'alipay_auth',
                r'AlipayCallback', r'alipay_callback',
                r'AlipayUser', r'alipay_user',
                r'AlipaySdk', r'alipay_sdk',
                r'AlipayAuthActivity', r'alipay_auth_activity',
                r'payResult', r'aliPayResult',
                r'AuthResult', r'authResult',
                r'ali_auth', r'ali_login',
                r'ali_user_id', r'ali_user_info',
                r'alipay_openid', r'alipay_uid',
                r'com_alipay', r'APAuth',
            ],
            'string_patterns': [
                r'alipay', r'支付宝', r'ali_pay',
                r'alipay_sdk', r'alipay_auth',
                r'alipay\.com', r'alipay-objects\.com',
                r'https://auth\.alipay\.com',
                r'https://openapi\.alipay\.com',
                r'https://openapi\.alipaydev\.com',
                r'https://app\.alipay\.com',
                r'app_id=[0-9]+',
                r'alipay_auth_code',
                r'alipay_refresh_token',
                r'alipay_user_id',
                r'auth_code', r'授权码',
                r'pid=[0-9]+',
            ],
            'url_patterns': [
                r'alipay\.com',
                r'alipay-objects\.com',
                r'alipaydev\.com',
                r'auth\.alipay\.com',
                r'openapi\.alipay\.com',
            ],
        },
        'weibo': {
            'name': '微博登录',
            'icon': '📱',
            'risk': '中',
            'patterns': [
                (r'com\.sina\.weibo', '微博SDK'),
                (r'com\.sina\.open', '新浪开放平台'),
                (r'com\.sina\.sso', '微博SSO'),
                (r'com\.weibo\.sdk', '微博SDK'),
                (r'com\.sina\.account', '新浪账户'),
            ],
            'code_patterns': [
                r'WeiboLogin', r'weibo_login', r'weibo_auth',
                r'WeiboToken', r'weibo_token',
                r'WeiboAuth', r'weibo_auth',
                r'WeiboCallback', r'weibo_callback',
                r'WeiboUser', r'weibo_user',
                r'WeiboSdk', r'weibo_sdk',
                r'SsoHandler', r'sso_handler',
                r'WeiboAuthActivity', r'WBShareActivity',
                r'WeiboDialog', r'weibo_dialog',
                r'AccessTokenKeeper', r'accessTokenKeeper',
            ],
            'string_patterns': [
                r'weibo', r'微博', r'sina',
                r'api\.weibo\.com',
                r'open\.weibo\.com',
                r'graph\.weibo\.com',
                r'weibo\.com',
                r'sina\.com',
                r'redirect_uri',
                r'client_id=[0-9]+',
                r'appkey=[0-9]+',
                r'https://api\.weibo\.com/oauth2',
            ],
            'url_patterns': [
                r'api\.weibo\.com',
                r'open\.weibo\.com',
                r'graph\.weibo\.com',
                r'weibo\.com',
            ],
        },
        'google': {
            'name': 'Google登录',
            'icon': '🔵',
            'risk': '低',
            'patterns': [
                (r'com\.google\.android\.gms\.auth', 'Google Auth'),
                (r'com\.google\.android\.gms\.common\.api', 'Google API'),
                (r'com\.google\.android\.gms\.signin', 'Google Sign-In'),
                (r'com\.google\.android\.gms\.identity', 'Google Identity'),
                (r'com\.google\.firebase\.auth', 'Firebase Auth'),
                (r'com\.google\.identity', 'Google Identity'),
                (r'com\.google\.apis\.auth', 'Google APIs Auth'),
            ],
            'code_patterns': [
                r'GoogleSignIn', r'google_sign_in', r'google_login',
                r'GoogleSignInClient', r'GoogleSignInAccount',
                r'GoogleSignInOptions', r'SignInButton',
                r'getIdToken', r'getServerAuthCode',
                r'FirebaseAuth', r'firebase_auth',
                r'AuthCredential', r'auth_credential',
                r'GoogleAuthUtil', r'google_auth_util',
                r'GoogleToken', r'google_token',
                r'GoogleLogin', r'google_login',
                r'google_sign_in_activity',
                r'R\.styleable\.SignInButton',
                r'com\.google\.android\.gms\.common\.api\.SignIn',
            ],
            'string_patterns': [
                r'google\.com/signin',
                r'google\.com/accounts',
                r'accounts\.google\.com',
                r'google\.com/identity',
                r'googleapis\.com/auth',
                r'google\.com/login',
                r'google\.com/oauth',
                r'firebase\.com',
                r'googleusercontent\.com',
                r'client_id=[0-9]+\.apps\.googleusercontent\.com',
                r'firebase_app_id',
                r'google_sign_in',
                r'google_login',
                r'gmail\.com',
                r'googlemail\.com',
            ],
            'url_patterns': [
                r'accounts\.google\.com',
                r'googleapis\.com',
                r'googleusercontent\.com',
                r'firebase\.com',
                r'google\.com',
            ],
        },
        'facebook': {
            'name': 'Facebook登录',
            'icon': '👍',
            'risk': '中',
            'patterns': [
                (r'com\.facebook\.login', 'Facebook Login'),
                (r'com\.facebook\.auth', 'Facebook Auth'),
                (r'com\.facebook\.react', 'Facebook React'),
                (r'com\.facebook\.account', 'Facebook Account'),
                (r'com\.facebook\.FBAuth', 'Facebook Auth'),
                (r'com\.facebook\.FBLogin', 'Facebook Login'),
            ],
            'code_patterns': [
                r'FacebookLogin', r'facebook_login', r'facebook_auth',
                r'LoginButton', r'login_button',
                r'ProfileTracker', r'profile_tracker',
                r'AccessToken', r'access_token',
                r'FacebookCallback', r'facebook_callback',
                r'FacebookSdk', r'facebook_sdk',
                r'LoginManager', r'login_manager',
                r'FacebookAuth', r'facebook_auth',
                r'facebook_token', r'facebook_user',
                r'com\.facebook\.FBSDK',
                r'CallbackManager', r'callback_manager',
                r'GraphRequest', r'graph_request',
                r'GraphResponse', r'graph_response',
            ],
            'string_patterns': [
                r'facebook\.com/login',
                r'facebook\.com/dialog',
                r'facebook\.com/oauth',
                r'graph\.facebook\.com',
                r'facebook\.com/v\d+\.\d+/',
                r'facebook\.com/dialog/oauth',
                r'fb\.com',
                r'facebook\.me',
                r'facebook\.com',
                r'fb_',
                r'facebook_app_id',
                r'facebook_login',
                r'facebook_token',
                r'fb_api',
                r'fb_sdk',
            ],
            'url_patterns': [
                r'facebook\.com',
                r'graph\.facebook\.com',
                r'fbcdn\.net',
                r'fb\.com',
                r'facebook\.me',
            ],
        },
        'apple': {
            'name': 'Apple登录',
            'icon': '🍎',
            'risk': '低',
            'patterns': [
                (r'com\.apple\.', 'Apple SDK'),
                (r'apple\.login', 'Apple Login'),
                (r'apple\.auth', 'Apple Auth'),
                (r'apple\.signin', 'Apple SignIn'),
                (r'authentication\b.*apple', 'Apple Auth'),
            ],
            'code_patterns': [
                r'AppleSignIn', r'apple_sign_in', r'apple_login',
                r'AppleLogin', r'apple_auth',
                r'AppleID', r'apple_id',
                r'AppleToken', r'apple_token',
                r'ASAuthorization', r'as_authorization',
                r'ASAuthorizationController',
                r'apple_id_credential',
                r'SignInWithApple', r'sign_in_with_apple',
                r'apple_credential',
                r'apple_user', r'apple_email',
                r'apple_full_name', r'apple_real_user',
            ],
            'string_patterns': [
                r'apple\.com/signin',
                r'apple\.com/auth',
                r'apple\.com/oauth',
                r'appleid\.apple\.com',
                r'apple\.com',
                r'apple_id',
                r'apple_sign_in',
                r'apple_login',
                r'sign_in_with_apple',
                r'apple_credential',
                r'apple\.com/auth/authorize',
                r'apple\.com/auth/token',
                r'apple\.com/auth/keys',
            ],
            'url_patterns': [
                r'apple\.com',
                r'appleid\.apple\.com',
            ],
        },
        'twitter': {
            'name': 'Twitter登录',
            'icon': '🐦',
            'risk': '低',
            'patterns': [
                (r'com\.twitter\.sdk', 'Twitter SDK'),
                (r'com\.twitter\.android', 'Twitter Android'),
                (r'com\.twitter\.auth', 'Twitter Auth'),
                (r'com\.twitter\.login', 'Twitter Login'),
                (r'com\.fabric\.sdk\.android', 'Fabric(Twitter)'),
                (r'com\.digital\.turbine', 'Twitter(Turbine)'),
            ],
            'code_patterns': [
                r'TwitterLogin', r'twitter_login', r'twitter_auth',
                r'TwitterAuth', r'twitter_auth',
                r'TwitterToken', r'twitter_token',
                r'TwitterApi', r'twitter_api',
                r'TwitterSession', r'twitter_session',
                r'TwitterUser', r'twitter_user',
                r'TwitterAuthConfig', r'twitter_auth_config',
                r'TwitterAuthClient', r'twitter_auth_client',
                r'fabric_login', r'FabricLogin',
                r'logIn', r'logOut',
                r'com\.twitter\.sdk\.android\.identity',
                r'com\.twitter\.sdk\.android\.core',
            ],
            'string_patterns': [
                r'twitter\.com/login',
                r'twitter\.com/oauth',
                r'twitter\.com/i/oauth2',
                r'api\.twitter\.com',
                r'twitter\.com',
                r'twitter_token',
                r'twitter_auth',
                r'twitter_login',
                r'twitter_key',
                r'twitter_secret',
                r'consumer_key',
                r'consumer_secret',
                r'oauth_token',
                r'oauth_token_secret',
                r'oauth_verifier',
                r'oauth_callback',
                r'oauth_nonce',
                r'oauth_signature',
                r'oauth_consumer_key',
                r'https://api\.twitter\.com/oauth',
            ],
            'url_patterns': [
                r'twitter\.com',
                r'api\.twitter\.com',
                r't\.co',
            ],
        },
    }

    # ── 登录相关通用代码模式 ────────────────────────────────
    GENERIC_LOGIN_PATTERNS = [
        r'OAuth', r'oauth',
        r'SSOLogin', r'sso_login',
        r'AuthActivity', r'auth_activity',
        r'LoginActivity', r'login_activity',
        r'AuthCallback', r'auth_callback',
        r'TokenManager', r'token_manager',
        r'AuthManager', r'auth_manager',
        r'LoginManager', r'login_manager',
        r'AuthProvider', r'auth_provider',
        r'SocialLogin', r'social_login',
        r'ThirdPartyLogin', r'third_party_login',
        r'ThirdLogin', r'third_login',
        r'PlatformLogin', r'platform_login',
        r'authorize', r'Authorize',
        r'authenticate', r'Authentication',
        r'access_token', r'accessToken',
        r'refresh_token', r'refreshToken',
        r'id_token', r'idToken',
        r'redirect_uri', r'redirectUri',
        r'callback_url', r'callbackUrl',
        r'login_url', r'loginUrl',
        r'auth_url', r'authUrl',
        r'client_id', r'clientId',
        r'client_secret', r'clientSecret',
        r'grant_type', r'grantType',
        r'response_type', r'responseType',
        r'scope', r'oAuthScope',
        r'state', r'oAuthState',
        r'code', r'authCode',
        r'login_platform', r'loginPlatform',
        r'platform_type', r'platformType',
        r'bind_platform', r'bindPlatform',
        r'unbind_platform', r'unbindPlatform',
        r'is_login', r'isLogin',
        r'is_logged', r'isLogged',
        r'logout', r'Logout',
        r'get_user_info', r'getUserInfo',
        r'get_platform_user', r'getPlatformUser',
        r'get_third_user', r'getThirdUser',
        r'login_success', r'loginSuccess',
        r'login_failed', r'loginFailed',
        r'login_cancel', r'loginCancel',
        r'third_party', r'thirdParty',
        r'social_platform', r'socialPlatform',
    ]

    @classmethod
    def detect_from_class_names(cls, class_names):
        """从DEX类名检测社交登录平台

        Args:
            class_names: list[str], DEX类名列表

        Returns:
            dict: {platform_key: {details}}
        """
        if not class_names:
            return {}

        combined = ' '.join(c.replace('/', '.').lstrip('L').rstrip(';') for c in class_names)
        results = {}

        for platform_key, platform in cls.PLATFORM_SIGNATURES.items():
            matched = []
            for pattern, label in platform.get('patterns', []):
                if re.search(pattern, combined):
                    matched.append(label)

            if matched:
                results[platform_key] = {
                    'name': platform['name'],
                    'icon': platform['icon'],
                    'risk': platform['risk'],
                    'matched_patterns': matched,
                    'pattern_count': len(matched),
                    'confidence': min(len(matched) * 20, 100),
                }

        return results

    @classmethod
    def detect_code_patterns(cls, class_names, strings):
        """检测社交登录相关代码模式

        Args:
            class_names: list[str], 类名列表
            strings: list[str], 字符串列表

        Returns:
            dict: {
                platform_key: {matched_patterns: [...], count: int},
                'generic': {matched_patterns: [...], count: int},
            }
        """
        if not class_names and not strings:
            return {}

        combined = ''
        if class_names:
            combined += ' '.join(c.replace('/', '.').lstrip('L').rstrip(';') for c in class_names)
        if strings:
            combined += ' '
            combined += ' '.join(strings)

        results = {}

        for platform_key, platform in cls.PLATFORM_SIGNATURES.items():
            matched = []
            for pattern in platform.get('code_patterns', []):
                if re.search(pattern, combined):
                    matched.append(pattern)
            if matched:
                results[platform_key] = {
                    'matched': matched,
                    'count': len(matched),
                }

        # 通用登录模式
        generic_matched = []
        for pattern in cls.GENERIC_LOGIN_PATTERNS:
            if re.search(pattern, combined):
                generic_matched.append(pattern)
        if generic_matched:
            results['generic'] = {
                'matched': generic_matched[:20],
                'count': len(generic_matched),
            }

        return results

    @classmethod
    def detect_from_strings(cls, strings):
        """从DEX字符串中检测社交登录平台特征

        Args:
            strings: list[str], 字符串列表

        Returns:
            dict: {platform_key: {matched_strings: [...], app_ids: [...], count: int}}
        """
        if not strings:
            return {}

        results = {}
        combined = ' '.join(strings)

        for platform_key, platform in cls.PLATFORM_SIGNATURES.items():
            matched = []
            app_ids = set()

            for pattern in platform.get('string_patterns', []):
                for m in re.finditer(pattern, combined, re.I):
                    matched.append(m.group())
                    # 尝试提取 AppID
                    if platform_key in ('wechat',) and re.match(r'wx[a-z0-9]{16,}', m.group()):
                        app_ids.add(m.group())
                    if platform_key in ('qq',) and re.match(r'tencent[0-9]{5,}', m.group()):
                        app_ids.add(m.group())
                    if platform_key in ('github', 'google') and 'client_id' in m.group().lower():
                        app_ids.add(m.group())

            if matched:
                results[platform_key] = {
                    'matched_strings': list(set(matched))[:15],
                    'app_ids': list(app_ids) if app_ids else [],
                    'count': len(set(matched)),
                }

        return results

    @classmethod
    def detect_urls(cls, strings):
        """从字符串中检测社交登录平台URL

        Args:
            strings: list[str], 字符串列表

        Returns:
            dict: {platform_key: [url_patterns]}
        """
        if not strings:
            return {}

        results = {}
        combined = ' '.join(strings)

        for platform_key, platform in cls.PLATFORM_SIGNATURES.items():
            matched = []
            for pattern in platform.get('url_patterns', []):
                if re.search(pattern, combined, re.I):
                    matched.append(pattern)
            if matched:
                results[platform_key] = matched

        return results

    @classmethod
    def analyze(cls, class_names=None, strings=None):
        """一站式社交登录检测分析

        Args:
            class_names: list[str], DEX类名列表
            strings: list[str], DEX字符串列表

        Returns:
            dict: 完整社交登录检测报告
        """
        result = {
            'platforms': {},
            'code_patterns': {},
            'string_matches': {},
            'urls': {},
            'summary': {},
            'score': 0,
            'level': '无社交登录',
        }

        # 1. SDK检测
        platform_sdks = cls.detect_from_class_names(class_names)
        result['platforms'] = platform_sdks

        # 2. 代码模式
        code_patterns = cls.detect_code_patterns(class_names, strings)
        result['code_patterns'] = code_patterns

        # 3. 字符串特征
        string_matches = cls.detect_from_strings(strings)
        result['string_matches'] = string_matches

        # 4. URL检测
        urls = cls.detect_urls(strings)
        result['urls'] = urls

        # 5. 合并分析
        all_platforms = set()
        all_platforms.update(platform_sdks.keys())
        all_platforms.update(k for k in code_patterns if k != 'generic')
        all_platforms.update(string_matches.keys())
        all_platforms.update(urls.keys())

        detected_platforms = {}
        for key in sorted(all_platforms):
            platform_info = cls.PLATFORM_SIGNATURES.get(key, {})
            detected = {
                'key': key,
                'name': platform_info.get('name', key),
                'icon': platform_info.get('icon', '🔗'),
                'risk': platform_info.get('risk', '低'),
                'has_sdk': key in platform_sdks,
                'has_code': key in code_patterns,
                'has_string': key in string_matches,
                'has_url': key in urls,
                'confidence': 0,
            }

            # 计算置信度
            confidence = 0
            if detected['has_sdk']:
                confidence += 40
            if detected['has_code']:
                confidence += 25
            if detected['has_string']:
                confidence += 20
            if detected['has_url']:
                confidence += 15

            # 附加信息
            if key in platform_sdks:
                detected['sdk_patterns'] = platform_sdks[key].get('matched_patterns', [])
            if key in code_patterns:
                detected['code_count'] = code_patterns[key].get('count', 0)
            if key in string_matches:
                detected['app_ids'] = string_matches[key].get('app_ids', [])
                detected['string_count'] = string_matches[key].get('count', 0)

            detected['confidence'] = min(confidence, 100)
            detected_platforms[key] = detected

        # 6. 综合评分
        total_score = 0
        platform_details = []
        has_any = bool(detected_platforms)

        for key, info in detected_platforms.items():
            weight = 1.0
            if info['risk'] == '高':
                weight = 1.5
            elif info['risk'] == '中':
                weight = 1.2
            platform_score = info['confidence'] * weight / 100 * 25
            total_score += platform_score
            platform_details.append({
                'key': key,
                'name': info['name'],
                'icon': info['icon'],
                'confidence': info['confidence'],
                'score': round(platform_score, 1),
                'risk': info['risk'],
            })

        total_score = min(100, round(total_score, 1))

        # 等级判定
        if total_score >= 60:
            level = '密集集成'
        elif total_score >= 30:
            level = '多平台集成'
        elif total_score >= 10:
            level = '少量集成'
        else:
            level = '无社交登录'

        result['detected_platforms'] = detected_platforms
        result['platform_details'] = sorted(platform_details, key=lambda x: -x['confidence'])
        result['total_platforms'] = len(detected_platforms)
        result['score'] = total_score
        result['level'] = level
        result['has_social_login'] = has_any

        # Summary
        if has_any:
            platform_names = [f"{p['icon']}{p['name']}({p['confidence']}%)"
                             for p in sorted(platform_details, key=lambda x: -x['confidence'])]
        else:
            platform_names = []

        result['summary'] = {
            'total_platforms': len(detected_platforms),
            'platform_names': platform_names,
            'score': total_score,
            'level': level,
            'has_wechat': 'wechat' in detected_platforms,
            'has_qq': 'qq' in detected_platforms,
            'has_github': 'github' in detected_platforms,
            'has_alipay': 'alipay' in detected_platforms,
            'has_weibo': 'weibo' in detected_platforms,
            'has_google': 'google' in detected_platforms,
            'has_facebook': 'facebook' in detected_platforms,
            'has_apple': 'apple' in detected_platforms,
            'has_twitter': 'twitter' in detected_platforms,
            'high_risk_count': sum(1 for p in detected_platforms.values() if p['risk'] == '高'),
            'medium_risk_count': sum(1 for p in detected_platforms.values() if p['risk'] == '中'),
        }

        return result


# ── 快捷函数 ──────────────────────────────────────────────────
def detect_social_login(class_names=None, strings=None):
    """一站式社交登录检测"""
    return SocialLoginDetector.analyze(class_names, strings)

def detect_wechat_login(class_names=None, strings=None):
    """检测微信登录集成"""
    result = SocialLoginDetector.analyze(class_names, strings)
    return result.get('detected_platforms', {}).get('wechat', {})

def detect_qq_login(class_names=None, strings=None):
    """检测QQ登录集成"""
    result = SocialLoginDetector.analyze(class_names, strings)
    return result.get('detected_platforms', {}).get('qq', {})

def detect_github_login(class_names=None, strings=None):
    """检测GitHub登录集成"""
    result = SocialLoginDetector.analyze(class_names, strings)
    return result.get('detected_platforms', {}).get('github', {})

def detect_alipay_login(class_names=None, strings=None):
    """检测支付宝登录集成"""
    result = SocialLoginDetector.analyze(class_names, strings)
    return result.get('detected_platforms', {}).get('alipay', {})