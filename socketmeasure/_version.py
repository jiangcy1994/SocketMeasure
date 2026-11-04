"""版本号单一来源。

`/api/health`、`/api/state` 与面板页面（页头/页脚）均引用这里的 `__version__`，
pyproject.toml / uv.lock 中的版本保持同步。发版时只改本文件。
"""

__version__ = "0.2.0"
