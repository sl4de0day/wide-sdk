import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from wide_sdk.database import (
    DatabaseClient,
    assess_sql_risk,
    is_query_readonly,
    mask_dsn,
    parse_database_target,
)
from wide_sdk.tools import db_audit_tool, db_inspect_schema_tool, db_query_tool


class TestDatabase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "app.sqlite"
        conn = sqlite3.connect(self.db_path)
        conn.executescript(
            """
            CREATE TABLE users (
                id INTEGER PRIMARY KEY,
                email TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                api_token TEXT NOT NULL
            );
            CREATE TABLE invoices (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id),
                amount_cents INTEGER NOT NULL
            );
            INSERT INTO users (id, email, password_hash, api_token)
            VALUES (1, 'alice@example.com', '5f4dcc3b5aa765d61d8327deb882cf99', 'tok_secret_123');
            INSERT INTO invoices (id, user_id, amount_cents) VALUES (10, 1, 4900);
            """
        )
        conn.commit()
        conn.close()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_masking_and_spec_repr_never_leak_passwords(self) -> None:
        raw = "postgresql://admin:s3cr3tPass@db.internal:5432/prod?sslmode=disable"
        self.assertEqual(mask_dsn(raw), "postgresql://admin:****@db.internal:5432/prod?sslmode=disable")
        spec = parse_database_target(raw, environment="prod", read_only=False)
        self.assertEqual(spec.kind, "postgres")
        self.assertEqual(spec.ssl_mode, "disable")
        self.assertNotIn("s3cr3tPass", repr(spec))
        self.assertNotIn("s3cr3tPass", str(spec))

    def test_sql_risk_and_readonly_detection(self) -> None:
        self.assertEqual(assess_sql_risk("DROP TABLE users")[0], True)
        self.assertEqual(assess_sql_risk("DELETE FROM users")[0], True)
        self.assertEqual(assess_sql_risk("UPDATE users SET active = 0 WHERE 1=1")[0], True)
        self.assertEqual(assess_sql_risk("SELECT 1; -- ok\nDROP TABLE users")[0], True)
        self.assertEqual(assess_sql_risk("SELECT 'DROP TABLE users' AS txt")[0], False)
        self.assertEqual(assess_sql_risk("DELETE FROM users WHERE id = 1")[0], False)
        self.assertTrue(is_query_readonly("SELECT id FROM users WHERE id = ?"))
        self.assertFalse(is_query_readonly("SELECT 1; DELETE FROM users WHERE id = 1"))

    def test_sqlite_client_queries_schema_and_guards(self) -> None:
        with DatabaseClient(str(self.db_path), read_only=True) as ro:
            res = ro.query("SELECT id, email FROM users WHERE id = ?", (1,))
            self.assertEqual(res.row_count, 1)
            self.assertEqual(res.rows[0]["email"], "alice@example.com")

            with self.assertRaises(PermissionError):
                ro.execute("DELETE FROM users WHERE id = 1")

            schema = ro.inspect_schema()
            names = [t.name for t in schema.tables]
            self.assertEqual(names, ["invoices", "users"])
            inv = [t for t in schema.tables if t.name == "invoices"][0]
            self.assertEqual(inv.row_count, 1)
            self.assertEqual(inv.foreign_keys[0].ref_table, "users")

            findings = ro.audit_security()
            cats = {f.category for f in findings}
            self.assertIn("pii-discovery", cats)
            self.assertIn("weak-credential-storage", cats)

        with DatabaseClient(str(self.db_path), read_only=False) as rw:
            with self.assertRaises(PermissionError):
                rw.execute("DROP TABLE invoices")
            rw.execute("DROP TABLE invoices", allow_destructive=True)
            schema_after = rw.inspect_schema()
            self.assertEqual([t.name for t in schema_after.tables], ["users"])

    def test_ai_tools_redact_secret_columns(self) -> None:
        ctx = {"working_directory": self.temp_dir.name}
        schema_res = db_inspect_schema_tool.execute({"target": "app.sqlite"}, ctx)
        self.assertTrue(schema_res.success)
        self.assertIn("invoices", schema_res.output)

        query_res = db_query_tool.execute(
            {"target": "app.sqlite", "sql": "SELECT id, email, password_hash, api_token FROM users WHERE id = ?", "params": [1]},
            ctx,
        )
        self.assertTrue(query_res.success)
        payload = json.loads(query_res.output)
        self.assertEqual(payload["rows"][0]["email"], "alice@example.com")
        self.assertEqual(payload["rows"][0]["password_hash"], "[REDACTED]")
        self.assertEqual(payload["rows"][0]["api_token"], "[REDACTED]")

        blocked = db_query_tool.execute({"target": "app.sqlite", "sql": "DROP TABLE users"}, ctx)
        self.assertFalse(blocked.success)

        audit_res = db_audit_tool.execute({"target": "app.sqlite", "environment": "prod"}, ctx)
        self.assertTrue(audit_res.success)
        findings = json.loads(audit_res.output)
        self.assertTrue(any(f["severity"] == "CRITICAL" for f in findings))


if __name__ == "__main__":
    unittest.main()
