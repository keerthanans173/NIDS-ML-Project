import sqlite3
import os

db_path = "database.db"
conn = sqlite3.connect(db_path)
c = conn.cursor()

# Get existing columns
columns_info = c.execute("PRAGMA table_info(predictions)").fetchall()
existing_cols = {col[1] for col in columns_info}
print("Existing columns in predictions:", existing_cols)

new_columns = [
    ("protocol_type", "TEXT DEFAULT 'tcp'"),
    ("service", "TEXT DEFAULT 'http'"),
    ("flag", "TEXT DEFAULT 'SF'"),
    ("src_bytes", "REAL DEFAULT 0.0"),
    ("dst_bytes", "REAL DEFAULT 0.0"),
    ("count", "INTEGER DEFAULT 1"),
    ("serror_rate", "REAL DEFAULT 0.0"),
    ("source_ip", "TEXT DEFAULT '192.168.1.105'"),
    ("is_flagged", "BOOLEAN DEFAULT 0"),
    ("analyst_status", "TEXT DEFAULT 'New'"),
    ("analyst_notes", "TEXT")
]

for col_name, col_def in new_columns:
    if col_name not in existing_cols:
        try:
            sql = f"ALTER TABLE predictions ADD COLUMN {col_name} {col_def};"
            c.execute(sql)
            print(f"Added column: {col_name}")
        except Exception as e:
            print(f"Error adding {col_name}: {e}")

conn.commit()
columns_info_after = c.execute("PRAGMA table_info(predictions)").fetchall()
print("Columns after migration:", [col[1] for col in columns_info_after])
conn.close()
