"""技能读取器 - 从文件系统读取 SKILL.md 逆向技能文档，参考 mHook SkillReader.java 移植"""
import os
import glob

MAX_SKILL_BYTES = 100 * 1024  # 100KB


class SkillReader:
    """从 skills 目录读取逆向技能文档"""

    _skills_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ai", "skills")

    @classmethod
    def _get_skills_dir(cls) -> str:
        return cls._skills_dir

    @classmethod
    def list_skills(cls) -> list:
        """列出所有可用技能名称"""
        skills_dir = cls._get_skills_dir()
        if not os.path.isdir(skills_dir):
            return []
        result = []
        for entry in os.listdir(skills_dir):
            skill_path = os.path.join(skills_dir, entry, "SKILL.md")
            if os.path.isfile(skill_path):
                result.append(entry)
        result.sort()
        return result

    @classmethod
    def read_skill(cls, name: str) -> str:
        """读取指定技能的 SKILL.md 内容"""
        if not name:
            return None
        skill_path = os.path.join(cls._get_skills_dir(), name, "SKILL.md")
        if not os.path.isfile(skill_path):
            return None
        try:
            with open(skill_path, "r", encoding="utf-8") as f:
                content = f.read(MAX_SKILL_BYTES)
                # Check if there's more
                rest = f.read(1)
                if rest:
                    return content + "\n...[技能文档过长已截断]"
                return content
        except Exception:
            return None