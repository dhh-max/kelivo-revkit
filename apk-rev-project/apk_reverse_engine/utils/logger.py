import sys
from datetime import datetime

class Logger:
    """日志工具"""

    LEVELS = {'DEBUG': 0, 'INFO': 1, 'WARN': 2, 'ERROR': 3}

    def __init__(self, name='REngine', level='INFO'):
        self.name = name
        self.level = self.LEVELS.get(level.upper(), 1)
        self.logs = []
        self.errors = 0
        self.warnings = 0

    def _log(self, level, msg):
        if self.LEVELS.get(level, 0) >= self.level:
            ts = datetime.now().strftime('%H:%M:%S.%f')[:-3]
            line = f'[{ts}][{level:5s}][{self.name}] {msg}'
            self.logs.append(line)
            print(line, file=sys.stderr)  # fallback before logging is ready
            if level == 'ERROR': self.errors += 1
            if level == 'WARN': self.warnings += 1

    def debug(self, msg): self._log('DEBUG', msg)
    def info(self, msg): self._log('INFO', msg)
    def warn(self, msg): self._log('WARN', msg)
    def error(self, msg): self._log('ERROR', msg)

    def get_logs(self):
        return '\n'.join(self.logs)

    def get_last_logs(self, n=10):
        return '\n'.join(self.logs[-n:])

    def get_stats(self):
        return {'total_logs': len(self.logs), 'errors': self.errors, 'warnings': self.warnings}

    def clear(self):
        self.logs.clear()
        self.errors = 0
        self.warnings = 0
