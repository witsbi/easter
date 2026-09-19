from kernel import Kernel

k = Kernel()

with k.connect() as conn:
    print(conn.execute("PRAGMA foreign_keys").fetchone()[0])
    print(conn.execute("PRAGMA recursive_triggers").fetchone()[0])
