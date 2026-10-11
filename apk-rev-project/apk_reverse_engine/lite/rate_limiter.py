# -*- coding: utf-8 -*-
"""rate_limiter — 五维限流 + AIMD 自适应 TPM（源自 RelayGo lib/services/rate_limiter.dart）

完整移植了 RelayGo 的限流核心算法，可直接用于 KE 的 AI 调用层：
  1. TokenBucket（令牌桶，支持突发倍数）
  2. SlidingWindow（滑动窗口计数器，按精确时间窗统计）
  3. RateLimiter.checkInbound() — IP / 全局 RPM 入口拦截
  4. RateLimiter.checkKey()     — key RPM（令牌桶）+ key TPM（滑动窗口）
  5. RateLimiter.recordTokens() — 响应后记账 + AIMD 加性增
  6. RateLimiter.recordUpstreamTpmLimit() — 遇上游 429 后 AIMD 乘性减
  7. RateLimiter.isRecoverableTpmLimit() — 判定 429 是否可恢复

Python 标准库实现（可选依赖：无），单文件、可直接嵌入 code_runner 环境。

对外 API:
  - TokenBucket(capacity, refill_per_sec)   .try_consume(cost=1) / .wait_seconds_for(cost)
  - SlidingWindow(window_ms)                .record(w) / .sum() / .count() / .retry_after_s()
  - RateLimiter(**kwargs)                   .check_inbound(ip) / .check_key(key, model='')
                                            .consume_key(key) / .record_tokens(key, tokens)
                                            .record_upstream_tpm_limit(key, model, usage)
                                            .snapshot() / .reset()
"""
from __future__ import annotations
import time, math
from typing import Optional, Dict, List, Tuple


# ── 默认常量（对齐 RelayGo Constants） ────────────────────────
DEFAULT_BURST_MULTIPLIER = 2.0
DEFAULT_TOKEN_RATE_LIMIT_PER_MINUTE = 0          # 0 = 不限
DEFAULT_IP_RATE_LIMIT_PER_MINUTE = 60
DEFAULT_GLOBAL_RPM_LIMIT = 0                     # 0 = 不限
DEFAULT_ADAPTIVE_TPM_ENABLED = True
TPM_AIMD_UP = 0.05                               # 加性增系数
TPM_AIMD_DOWN = 0.5                              # 乘性减系数

# 上游 429 body 中常见「TPM 限流」关键词（用于判定可恢复）
TPM_RECOVERABLE_KEYWORDS = (
    'rate_limit', 'rate limit', 'too many requests', 'rpm', 'tpm',
    'tokens per minute', 'requests per minute', 'quota',
    'token limit', 'quota_exceeded', 'quota exceeded',
)


# ── 令牌桶 ──────────────────────────────────────────────────
class TokenBucket:
    """令牌桶：容量 = 速率 × 突发倍数，空闲时累积令牌吸收突发。"""

    __slots__ = ('tokens', 'capacity', 'refill_per_sec', '_last')

    def __init__(self, capacity, refill_per_sec, now_s=None):
        self.capacity = float(capacity)
        self.refill_per_sec = float(refill_per_sec)
        self.tokens = self.capacity
        self._last = now_s if now_s is not None else time.time()

    def _refill(self, now_s=None):
        now = now_s if now_s is not None else time.time()
        dt = now - self._last
        if dt <= 0:
            return
        self.tokens = min(self.capacity, max(0.0, self.tokens + dt * self.refill_per_sec))
        self._last = now

    def try_consume(self, cost=1.0, now_s=None) -> bool:
        self._refill(now_s)
        if self.tokens >= cost:
            self.tokens -= cost
            return True
        return False

    def allow(self, now_s=None) -> bool:
        return self.try_consume(now_s=now_s)

    def wait_seconds_for(self, cost=1.0) -> int:
        if self.refill_per_sec <= 0:
            return 60
        missing = cost - self.tokens
        if missing <= 0:
            return 0
        return int(math.ceil(missing / self.refill_per_sec))


# ── 滑动窗口 ────────────────────────────────────────────────
class SlidingWindow:
    """滑动窗口：精确统计「最近 N 毫秒」内的事件计数或权重之和。"""

    __slots__ = ('window_ms', '_events')

    def __init__(self, window_ms: int):
        self.window_ms = int(window_ms)
        self._events: List[Tuple[int, int]] = []  # (ts_ms, weight)

    def _trim(self, now_ms: int):
        cutoff = now_ms - self.window_ms
        # 保留 >= cutoff 的事件
        self._events = [e for e in self._events if e[0] >= cutoff]

    def record(self, weight: int = 1, now_ms: Optional[int] = None):
        now = now_ms if now_ms is not None else int(time.time() * 1000)
        self._events.append((now, weight))
        self._trim(now)

    def sum(self, now_ms: Optional[int] = None) -> int:
        now = now_ms if now_ms is not None else int(time.time() * 1000)
        self._trim(now)
        return sum(w for _, w in self._events)

    def count(self, now_ms: Optional[int] = None) -> int:
        now = now_ms if now_ms is not None else int(time.time() * 1000)
        self._trim(now)
        return len(self._events)

    def retry_after_s(self, now_ms: Optional[int] = None) -> int:
        now = now_ms if now_ms is not None else int(time.time() * 1000)
        self._trim(now)
        if not self._events:
            return 0
        oldest = self._events[0][0]
        ms = self.window_ms - (now - oldest)
        if ms <= 0:
            return 0
        return int(math.ceil(ms / 1000.0))

    def clear(self):
        self._events.clear()


# ── 限流结果 ────────────────────────────────────────────────
class RateLimitResult:
    __slots__ = ('allowed', 'dimension', 'retry_after_s', 'message')

    def __init__(self, allowed, dimension='', retry_after_s=0, message=''):
        self.allowed = bool(allowed)
        self.dimension = dimension
        self.retry_after_s = int(retry_after_s)
        self.message = message

    @classmethod
    def allow(cls):
        return cls(True)

    @classmethod
    def deny(cls, dimension, retry_after_s=1, message=''):
        return cls(False, dimension, retry_after_s, message)

    def to_dict(self):
        return {
            'allowed': self.allowed,
            'dimension': self.dimension,
            'retryAfterSeconds': self.retry_after_s,
            'message': self.message,
        }

    def __repr__(self):
        return 'RateLimitResult(allowed=%s dim=%r retry=%ds)' % (
            self.allowed, self.dimension, self.retry_after_s)


# ── API Key 最小结构（与 RelayGo ApiKey 对齐字段） ───────────
class ApiKey:
    __slots__ = ('id', 'name', 'max_requests_per_minute', 'provider', 'model_allowlist')

    def __init__(self, id, name='', max_requests_per_minute=0, provider='',
                 model_allowlist=None):
        self.id = id
        self.name = name or id
        self.max_requests_per_minute = int(max_requests_per_minute or 0)
        self.provider = provider
        self.model_allowlist = list(model_allowlist) if model_allowlist else None


# ── 高级限流器 ──────────────────────────────────────────────
class RateLimiter:
    """五维限流 + AIMD 自适应 TPM。"""

    def __init__(self,
                 burst_multiplier: float = DEFAULT_BURST_MULTIPLIER,
                 tokens_per_minute_per_key: int = DEFAULT_TOKEN_RATE_LIMIT_PER_MINUTE,
                 requests_per_minute_per_ip: int = DEFAULT_IP_RATE_LIMIT_PER_MINUTE,
                 global_requests_per_minute: int = DEFAULT_GLOBAL_RPM_LIMIT,
                 adaptive_tpm_enabled: bool = DEFAULT_ADAPTIVE_TPM_ENABLED,
                 enabled: bool = True,
                 tpm_aimd_up: float = TPM_AIMD_UP,
                 tpm_aimd_down: float = TPM_AIMD_DOWN):
        self.burst_multiplier = float(burst_multiplier)
        self.tokens_per_minute_per_key = int(tokens_per_minute_per_key)
        self.requests_per_minute_per_ip = int(requests_per_minute_per_ip)
        self.global_requests_per_minute = int(global_requests_per_minute)
        self.adaptive_tpm_enabled = bool(adaptive_tpm_enabled)
        self.enabled = bool(enabled)
        self.tpm_aimd_up = float(tpm_aimd_up)
        self.tpm_aimd_down = float(tpm_aimd_down)

        self._key_buckets: Dict[str, TokenBucket] = {}
        self._key_token_windows: Dict[str, SlidingWindow] = {}
        self._ip_windows: Dict[str, SlidingWindow] = {}
        self._global_window = SlidingWindow(60 * 1000)
        self.denials: Dict[str, int] = {}
        self._learned_tpm: Dict[str, int] = {}
        self._tpm_stable_ms: Dict[str, int] = {}

    # ── 入口级（IP / 全局） ────────────────────────────
    def check_inbound(self, client_ip: str = '') -> RateLimitResult:
        if not self.enabled:
            return RateLimitResult.allow()
        if self.global_requests_per_minute > 0:
            if self._global_window.count() >= self.global_requests_per_minute:
                self._deny('global')
                return RateLimitResult.deny(
                    'global',
                    retry_after_s=self._global_window.retry_after_s(),
                    message='global rpm limit reached (%d/min)' % self.global_requests_per_minute,
                )
        if self.requests_per_minute_per_ip > 0 and client_ip:
            w = self._ip_windows.get(client_ip)
            if w is None:
                w = SlidingWindow(60 * 1000)
                self._ip_windows[client_ip] = w
            if w.count() >= self.requests_per_minute_per_ip:
                self._deny('ip')
                return RateLimitResult.deny(
                    'ip',
                    retry_after_s=w.retry_after_s(),
                    message='ip rpm limit reached (%d/min)' % self.requests_per_minute_per_ip,
                )
        return RateLimitResult.allow()

    def record_inbound(self, client_ip: str = '') -> None:
        if not self.enabled:
            return
        if self.global_requests_per_minute > 0:
            self._global_window.record(1)
        if self.requests_per_minute_per_ip > 0 and client_ip:
            w = self._ip_windows.get(client_ip)
            if w is None:
                w = SlidingWindow(60 * 1000)
                self._ip_windows[client_ip] = w
            w.record(1)

    # ── Key 级（RPM 令牌桶 + TPM 滑动窗口） ─────────────
    def check_key(self, key: ApiKey, model: str = '') -> RateLimitResult:
        if not self.enabled:
            return RateLimitResult.allow()

        eff_tpm = self._effective_tpm_limit(key, model)
        if eff_tpm is not None and eff_tpm > 0:
            tw = self._key_token_windows.get(key.id)
            used = tw.sum() if tw else 0
            if used >= eff_tpm:
                self._deny('key_tpm')
                return RateLimitResult.deny(
                    'key_tpm',
                    retry_after_s=(tw.retry_after_s() if tw else 1),
                    message='key %s tpm limit reached' % key.name,
                )

        rpm = key.max_requests_per_minute
        if rpm <= 0:
            return RateLimitResult.allow()
        bucket = self._bucket_for(key)
        # 探测不消耗
        probe = TokenBucket(bucket.capacity, bucket.refill_per_sec)
        probe.tokens = bucket.tokens
        if not probe.try_consume():
            self._deny('key_rpm')
            return RateLimitResult.deny(
                'key_rpm',
                retry_after_s=bucket.wait_seconds_for(1),
                message='key %s rpm limit reached (%d/min)' % (key.name, rpm),
            )
        return RateLimitResult.allow()

    def allows(self, key: ApiKey, model: str = '') -> bool:
        return self.check_key(key, model=model).allowed

    def consume_key(self, key: ApiKey) -> bool:
        if not self.enabled:
            return True
        if key.max_requests_per_minute <= 0:
            return True
        return self._bucket_for(key).try_consume()

    def record_tokens(self, key: ApiKey, tokens: int, model: str = '') -> None:
        if not self.enabled or tokens <= 0:
            return
        tw = self._key_token_windows.get(key.id)
        if tw is None:
            tw = SlidingWindow(60 * 1000)
            self._key_token_windows[key.id] = tw
        tw.record(tokens)

        # AIMD 加性增：累计约 0.75 个窗口的稳定用量后，小幅上调学到的上限
        if self.adaptive_tpm_enabled:
            keyed = '%s|%s' % (key.id, model)
            if keyed in self._learned_tpm:
                stable = self._tpm_stable_ms.get(keyed, 0) + tokens
                threshold = 60 * 1000 * 3 // 4   # 45s
                if stable >= threshold:
                    self._tpm_stable_ms[keyed] = 0
                    learned = self._learned_tpm[keyed]
                    bumped = int(round(learned * (1 + self.tpm_aimd_up)))
                    if bumped > learned:
                        self._learned_tpm[keyed] = bumped
                else:
                    self._tpm_stable_ms[keyed] = stable

    def record_upstream_tpm_limit(self, key: ApiKey, model: str, usage_this_window: int) -> None:
        """遇上游 429 TPM 限流时调用：AIMD 乘性减。"""
        if not self.adaptive_tpm_enabled:
            return
        keyed = '%s|%s' % (key.id, model)
        current = self._learned_tpm.get(keyed)
        base = usage_this_window if usage_this_window > 0 else (current or 0)
        if base <= 0:
            return
        reduced = int(round(base * self.tpm_aimd_down))
        if reduced < 1:
            return
        learned = reduced if (current is None or reduced < current) else int(round(current * 0.85))
        self._learned_tpm[keyed] = max(1, learned)
        self._tpm_stable_ms[keyed] = 0

    def _effective_tpm_limit(self, key: ApiKey, model: str) -> Optional[int]:
        if self.tokens_per_minute_per_key > 0:
            return self.tokens_per_minute_per_key
        if self.adaptive_tpm_enabled:
            learned = self._learned_tpm.get('%s|%s' % (key.id, model))
            if learned is not None and learned > 0:
                return int(math.floor(learned * 0.95))
        return None

    def tpm_used(self, key: ApiKey) -> int:
        tw = self._key_token_windows.get(key.id)
        return tw.sum() if tw else 0

    def tpm_wait_ms(self, key: ApiKey) -> int:
        tw = self._key_token_windows.get(key.id)
        return tw.retry_after_s() * 1000 if tw else 0

    def reset_learn(self, key: ApiKey) -> None:
        prefix = '%s|' % key.id
        for k in list(self._learned_tpm.keys()):
            if k.startswith(prefix):
                del self._learned_tpm[k]
                if k in self._tpm_stable_ms:
                    del self._tpm_stable_ms[k]

    def _bucket_for(self, key: ApiKey) -> TokenBucket:
        rpm = key.max_requests_per_minute
        refill = rpm / 60.0
        capacity = rpm * self.burst_multiplier
        existing = self._key_buckets.get(key.id)
        if existing is None or \
                abs(existing.refill_per_sec - refill) > 1e-4 or \
                abs(existing.capacity - capacity) > 1e-4:
            b = TokenBucket(capacity, refill)
            self._key_buckets[key.id] = b
            return b
        return existing

    def _deny(self, dimension: str):
        self.denials[dimension] = self.denials.get(dimension, 0) + 1

    def snapshot(self) -> dict:
        return {
            'enabled': self.enabled,
            'global_last_minute': self._global_window.count(),
            'tracked_ips': len(self._ip_windows),
            'tracked_keys': len(self._key_buckets),
            'denials': dict(self.denials),
            'limits': {
                'burst_multiplier': self.burst_multiplier,
                'tokens_per_minute_per_key': self.tokens_per_minute_per_key,
                'adaptive_tpm_enabled': self.adaptive_tpm_enabled,
                'learned_tpm_entries': len(self._learned_tpm),
                'requests_per_minute_per_ip': self.requests_per_minute_per_ip,
                'global_requests_per_minute': self.global_requests_per_minute,
            },
        }

    def reset(self):
        self._key_buckets.clear()
        self._key_token_windows.clear()
        self._ip_windows.clear()
        self._global_window.clear()
        self._learned_tpm.clear()
        self._tpm_stable_ms.clear()
        self.denials.clear()

    # ── 静态工具 ──────────────────────────────
    @staticmethod
    def is_recoverable_tpm_limit(status_code: int, body: str) -> bool:
        if status_code != 429:
            return False
        b = (body or '').lower()
        for kw in TPM_RECOVERABLE_KEYWORDS:
            if kw in b:
                return True
        return False


__all__ = [
    'TokenBucket',
    'SlidingWindow',
    'RateLimiter',
    'RateLimitResult',
    'ApiKey',
    'DEFAULT_BURST_MULTIPLIER',
    'TPM_AIMD_UP',
    'TPM_AIMD_DOWN',
    'TPM_RECOVERABLE_KEYWORDS',
]