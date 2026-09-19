from kernel import Kernel
import sqlite3

kernel = Kernel()

try:
    with kernel.connect() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO states (
                state_id,
                created_at,
                payload
            )
            VALUES (
                'state:genesis',
                '2099-01-01T00:00:00Z',
                '{"hacked":true}'
            )
            """
        )
        conn.commit()

except sqlite3.DatabaseError as exc:
    print(f"Blocked as expected: {exc}")
