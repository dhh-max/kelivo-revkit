"""AI 设置 - 接口配置、模型、超时、最大轮次"""
import json
import os

class AiSetting:
    _config_path = os.path.expanduser("~/.apk_reverse_engine/ai_config.json")
    _defaults = {
        "base_url": "",
        "api_key": "",
        "model": "",
        "max_tokens": 4096,
        "timeout": 120,
        "max_steps": 32,
    }

    @classmethod
    def _load(cls):
        try:
            with open(cls._config_path, "r") as f:
                data = json.load(f)
            merged = {**cls._defaults, **data}
            return merged
        except Exception:
            return dict(cls._defaults)

    @classmethod
    def _save(cls, cfg):
        os.makedirs(os.path.dirname(cls._config_path), exist_ok=True)
        with open(cls._config_path, "w") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)

    @classmethod
    def get(cls, key, default=None):
        return cls._load().get(key, default if default is not None else cls._defaults.get(key))

    @classmethod
    def set(cls, key, value):
        cfg = cls._load()
        cfg[key] = value
        cls._save(cfg)

    @classmethod
    def all(cls):
        return cls._load()

    @classmethod
    def update(cls, **kwargs):
        cfg = cls._load()
        cfg.update(kwargs)
        cls._save(cfg)

    @classmethod
    def base_url(cls):
        return cls.get("base_url", "")

    @classmethod
    def api_key(cls):
        return cls.get("api_key", "")

    @classmethod
    def model(cls):
        return cls.get("model", "")

    @classmethod
    def max_tokens(cls):
        return cls.get("max_tokens", 4096)

    @classmethod
    def timeout(cls):
        return cls.get("timeout", 120)

    @classmethod
    def max_steps(cls):
        return cls.get("max_steps", 32)
