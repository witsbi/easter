"""EASTER Enterprise token broker.

Userland, not kernel. This package never imports ``kernel.py`` and
never opens ``data/kernel.db`` directly -- the only kernel interaction
is through the same MCP stdio subprocess every other userland
component (gateway, console) already uses, via ``kernel_client.py``.
"""
