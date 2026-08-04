class SecurityAnalyzer:
    @staticmethod
    def analyze(manifest_simple, permissions, obfuscation_score, packers):
        issues = []
        score = 0
        for c in manifest_simple.get("components", []):
            if c.get("attrs", {}).get("debuggable") == "true":
                issues.append({"severity": "HIGH", "type": "可调试", "desc": "应用被标记为可调试"}); score += 3
            if c.get("attrs", {}).get("allowBackup") == "true":
                issues.append({"severity": "MEDIUM", "type": "数据备份", "desc": "允许应用数据备份"}); score += 2
            if c.get("attrs", {}).get("exported") == "true":
                issues.append({"severity": "MEDIUM", "type": "暴露组件", "desc": f"{c['type']}被导出"}); score += 1
        if packers:
            issues.append({"severity": "HIGH", "type": "加固壳", "desc": f"检测到: {', '.join(packers)}"}); score += 3
        if permissions.get("dangerous_count", 0) > 5:
            issues.append({"severity": "INFO", "type": "敏感权限", "desc": f"{permissions['dangerous_count']}个敏感权限"})
        return {"risk_score": min(score, 10), "risk_level": "CRITICAL" if score >= 8 else "HIGH" if score >= 5 else "MEDIUM" if score >= 2 else "LOW", "issues": issues}