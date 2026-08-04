import sys
from datetime import datetime
class Logger:
    LEVELS = {'DEBUG':0,'INFO':1,'WARN':2,'ERROR':3}
    def __init__(self, name="REngine", level="INFO"):
        self.name = name
        self.level = self.LEVELS.get(level, 1)
        self.logs = []
    def _log(self, level, msg):
        if self.LEVELS.get(level,0) >= self.level:
            ts = datetime.now().strftime("%H:%M:%S")
            line = f"[{ts}][{level:5s}] {msg}"
            self.logs.append(line)
            print(line, file=sys.stderr)
    def debug(self, msg): self._log("DEBUG", msg)
    def info(self, msg): self._log("INFO", msg)
    def warn(self, msg): self._log("WARN", msg)
    def error(self, msg): self._log("ERROR", msg)
    def get_logs(self): return "\n".join(self.logs)
