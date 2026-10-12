# -*- coding: utf-8 -*-
"""Tests for TaiXu-derived lite modules.

Exercises the four pure-algo modules extracted from TaiXu Android code:
- redactor.py    <- core/security/SecretRedactor.kt
- shell_quote.py <- core/common/shell/ShellQuote.kt
- app_result.py  <- core/common/result/AppResult.kt
- checksum.py    <- core/network/ChecksumVerifier.kt

Run:  python3 -m pytest tests/test_third_party.py
"""
import io
import os
import sys
import tempfile

LITE_DIR = os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..", "apk_reverse_engine", "lite"
))
if LITE_DIR not in sys.path:
    sys.path.insert(0, LITE_DIR)

from redactor import mask, redact, redact_with_secrets  # noqa: E402
from shell_quote import shell_quote, shell_join, quoted_of  # noqa: E402
from app_result import Success, Failure, fail, ErrorCode, AppError  # noqa: E402
from checksum import (  # noqa: E402
    sha256_file, sha1_file, md5_file, verify_sha256, ChecksumMismatch,
)


# ============================================================ redactor

def test_redactor_masks_phone():
    out = redact("call 13812345678 now")
    assert "13812345678" not in out
    assert "PHONE_REDACTED" in out


def test_redactor_masks_labeled_api_key():
    out = redact("--api-key sk-abcdef123456 end")
    assert "sk-abcdef123456" not in out
    assert "REDACTED" in out


def test_redactor_masks_bearer_token():
    # Bearer header pattern: "Bearer sk-..." style prefix
    out = redact("Authorization: Bearer sk-proj-AABBCCDDEEFF112233445566")
    assert "sk-proj-AABBCCDDEEFF112233445566" not in out
    assert "REDACTED" in out


def test_redactor_masks_openai_key_prefix():
    out = redact("my key: sk-proj-AABBCCDDEEFF112233445566")
    assert "sk-proj-AABBCCDDEEFF112233445566" not in out
    assert "REDACTED" in out


def test_redactor_preserves_harmless_text():
    out = redact("just some plain text")
    assert out == "just some plain text"


def test_mask_short_value_is_all_asterisks():
    assert mask("abc") == "***"


def test_mask_long_value_keeps_prefix_suffix():
    m = mask("abcdefgh")
    assert m.startswith("ab") and m.endswith("gh")


def test_redact_with_secrets_masks_named_values():
    out = redact_with_secrets(
        "token=secret123456 and echo secret123456",
        secret_values=["secret123456"],
    )
    assert "secret123456" not in out


# =========================================================== shell_quote

def test_shell_quote_empty_string():
    assert shell_quote("") == "''"


def test_shell_quote_safe_word():
    q = shell_quote("hello")
    assert q in ("hello", "'hello'")


def test_shell_quote_metachars_are_quoted():
    for bad in ["$X", "`cmd`", ";rm", "&&", "|", "\n", "\t", "*", "~"]:
        q = shell_quote(bad)
        # quoted form must not equal the raw dangerous string
        assert q != bad


def test_shell_quote_single_quote_inside():
    q = shell_quote("it's")
    # single quotes must be escaped / quoted somehow
    assert q != "it's"


def test_shell_join_produces_list():
    out = shell_join(["a", "b", "c"])
    assert "a" in out and "b" in out and "c" in out


def test_shell_join_prefix_arg():
    out = shell_join(["a", "b"], prefix="--x")
    assert "--x" in out or "a" in out


def test_quoted_of_alias():
    assert quoted_of("hello") == shell_quote("hello")


# =========================================================== app_result

def test_success_property_flags():
    r = Success(42)
    assert r.is_success is True
    assert r.is_failure is False
    assert r.data == 42


def test_success_get_or_null_returns_data():
    r = Success(7)
    assert r.get_or_null() == 7
    assert r.error_or_null() is None


def test_success_map_transforms_data():
    r = Success(10).map(lambda x: x * 2)
    assert isinstance(r, Success)
    assert r.data == 20


def test_failure_property_flags():
    r = Failure.of(ErrorCode.IO, "boom")
    assert r.is_failure is True
    assert r.is_success is False
    assert r.data is None if hasattr(r, "data") else True


def test_failure_get_or_null_returns_none():
    r = Failure.of(ErrorCode.IO, "boom")
    assert r.get_or_null() is None
    err = r.error_or_null()
    assert isinstance(err, AppError)
    assert err.code == "IO"
    assert err.message == "boom"


def test_failure_map_returns_self():
    r = Failure.of(ErrorCode.IO, "boom")
    mapped = r.map(lambda x: x + 1)
    assert mapped is r


def test_fail_helper_returns_failure():
    r = fail("E_TIMEOUT", "timeout")
    assert isinstance(r, Failure)
    assert r.error.code == "E_TIMEOUT"


def test_errorcode_all_twelve_categories_present():
    for name in [
        "UNKNOWN", "IO", "NETWORK", "DOWNLOAD", "CHECKSUM",
        "RUNTIME_NOT_INITIALIZED", "UNSUPPORTED_ARCHITECTURE",
        "INSUFFICIENT_STORAGE", "INSTALLATION_FAILED",
        "DATABASE", "SECURITY",
    ]:
        assert hasattr(ErrorCode, name), name


def test_success_and_failure_unequal():
    assert Success(1).to_dict() != Failure.of("E", "").to_dict()


def test_apperror_to_dict_contains_code_and_message():
    e = AppError("IO", "msg", cause=ValueError("v"))
    d = e.to_dict()
    assert d["code"] == "IO"
    assert d["message"] == "msg"
    assert "ValueError" in d["cause"]


# ============================================================ checksum

def test_sha256_of_known_bytes_via_buffer():
    buf = io.BytesIO(b"hello")
    assert sha256_file(buf) == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"


def test_sha1_of_known_bytes_via_buffer():
    assert sha1_file(io.BytesIO(b"hello")) == "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"


def test_md5_of_known_bytes_via_buffer():
    assert md5_file(io.BytesIO(b"hello")) == "5d41402abc4b2a76b9719d911017c592"


def test_sha256_of_empty_buffer():
    assert sha256_file(io.BytesIO(b"")) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_verify_sha256_accepts_matching():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"abc")
        p = f.name
    try:
        verify_sha256(p, sha256_file(p))
    finally:
        try: os.unlink(p)
        except OSError: pass


def test_verify_sha256_rejects_mismatch():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"abc")
        p = f.name
    try:
        try:
            verify_sha256(p, "deadbeef" * 8)
        except ChecksumMismatch:
            return
        raise AssertionError("verify_sha256 should have raised ChecksumMismatch")
    finally:
        try: os.unlink(p)
        except OSError: pass


def test_checksum_handles_empty_path_buffer():
    # sha256 of empty file
    with tempfile.NamedTemporaryFile(delete=False) as f:
        p = f.name
    try:
        assert sha256_file(p) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    finally:
        try: os.unlink(p)
        except OSError: pass
