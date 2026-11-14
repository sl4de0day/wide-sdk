import importlib
import os
import re
import shlex
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Sequence, Tuple, Union
from urllib.parse import parse_qs, unquote, urlparse

from .redact import (
    PII_COLUMN_RE,
    assess_sql_risk,
    is_query_readonly,
    mask_dsn,
    redact_rows,
)

DbKind = Literal["sqlite", "postgres", "mysql", "redis"]
DbEnvironment = Literal["local", "staging", "prod"]


@dataclass
class DatabaseConnectionSpec:
    kind: DbKind
    name: str
    environment: DbEnvironment = "local"
    read_only: bool = False
    host: Optional[str] = None
    port: Optional[int] = None
    database: Optional[str] = None
    file_path: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = field(default=None, repr=False)
    ssl_mode: Literal["default", "disable", "require", "verify-full"] = "default"
    reject_unauthorized: Optional[bool] = None

    def masked_target(self) -> str:
        if self.kind == "sqlite":
            return self.file_path or ":memory:"
        scheme = "postgresql" if self.kind == "postgres" else self.kind
        auth = f"{self.username}:****@" if self.password and self.username else (f"{self.username}@" if self.username else "")
        host = self.host or "localhost"
        port = f":{self.port}" if self.port else ""
        db = f"/{self.database}" if self.database else ""
        return f"{scheme}://{auth}{host}{port}{db}"

    def __str__(self) -> str:
        return self.masked_target()


@dataclass
class QueryResult:
    columns: List[str]
    rows: List[Dict[str, Any]]
    row_count: int
    changes: Optional[int] = None
    elapsed_ms: int = 0
    truncated: bool = False


@dataclass
class SchemaColumn:
    name: str
    data_type: str
    nullable: bool
    primary_key: bool
    default_value: Optional[str] = None


@dataclass
class ForeignKeyInfo:
    column: str
    ref_table: str
    ref_column: str


@dataclass
class SchemaTable:
    name: str
    table_type: Literal["table", "view"]
    columns: List[SchemaColumn]
    foreign_keys: List[ForeignKeyInfo] = field(default_factory=list)
    row_count: Optional[int] = None


@dataclass
class SchemaResult:
    kind: DbKind
    target: str
    tables: List[SchemaTable] = field(default_factory=list)
    redis_info: Optional[Dict[str, Any]] = None


@dataclass
class SecurityAuditFinding:
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "INFO"]
    category: str
    target: str
    message: str
    recommendation: str


def _is_localhost(host: Optional[str]) -> bool:
    h = (host or "").strip().lower()
    return h in ("", "localhost", "127.0.0.1", "::1")


def _quote_sql_ident(name: str, kind: DbKind) -> str:
    if kind == "mysql":
        return "`" + str(name).replace("`", "``") + "`"
    return '"' + str(name).replace('"', '""') + '"'


def _classify_hash_sample(val: Any) -> str:
    if not isinstance(val, str) or not val.strip():
        return "skip"
    s = val.strip()
    if re.match(r"^\$2[aby]\$|^\$argon2(id|i|d)\$|^\$scrypt\$|^pbkdf2[:$]", s):
        return "strong"
    if re.match(r"^[a-f0-9]{32}$", s, re.IGNORECASE):
        return "weak_md5"
    if re.match(r"^[a-f0-9]{40}$", s, re.IGNORECASE):
        return "weak_sha1"
    return "weak_plain"


def parse_database_target(
    target: str,
    *,
    working_directory: Optional[str] = None,
    name: Optional[str] = None,
    environment: DbEnvironment = "local",
    read_only: bool = False,
) -> DatabaseConnectionSpec:
    trimmed = str(target or "").strip()
    if not trimmed:
        raise ValueError("Database target URI or path cannot be empty.")

    if trimmed == ":memory:" or trimmed.startswith("sqlite://") or trimmed.startswith("file:") or "://" not in trimmed:
        raw_path = trimmed
        if raw_path.startswith("sqlite:///"):
            raw_path = raw_path[len("sqlite:///"):]
        elif raw_path.startswith("sqlite://"):
            raw_path = raw_path[len("sqlite://"):]
        elif raw_path.startswith("file:"):
            raw_path = raw_path[len("file:"):]
        if raw_path == ":memory:":
            resolved = ":memory:"
            alias = name or "memory-sqlite"
        else:
            base = Path(working_directory or os.getcwd())
            resolved = str((base / raw_path).resolve())
            alias = name or Path(resolved).name
        return DatabaseConnectionSpec(
            kind="sqlite",
            name=alias,
            environment=environment,
            read_only=bool(read_only),
            file_path=resolved,
        )

    parsed = urlparse(trimmed)
    scheme = parsed.scheme.lower()
    if scheme in ("postgres", "postgresql"):
        kind: DbKind = "postgres"
        default_port = 5432
    elif scheme in ("mysql", "mysql2"):
        kind = "mysql"
        default_port = 3306
    elif scheme in ("redis", "rediss"):
        kind = "redis"
        default_port = 6379
    else:
        raise ValueError(f"Unsupported database scheme '{scheme}'.")

    qs = parse_qs(parsed.query)
    ssl_param = ((qs.get("sslmode") or qs.get("ssl") or [""])[0]).lower()
    ssl_mode: Literal["default", "disable", "require", "verify-full"] = "default"
    reject_unauthorized: Optional[bool] = None
    if scheme == "rediss" or ssl_param in ("require", "true", "1"):
        ssl_mode = "require"
        reject_unauthorized = False
    elif ssl_param in ("verify-full", "verify-ca"):
        ssl_mode = "verify-full"
        reject_unauthorized = True
    elif ssl_param in ("disable", "false", "0"):
        ssl_mode = "disable"
        reject_unauthorized = False

    host = parsed.hostname or "localhost"
    port = parsed.port or default_port
    database = parsed.path.lstrip("/") if parsed.path else ("0" if kind == "redis" else "")
    username = unquote(parsed.username) if parsed.username else None
    password = unquote(parsed.password) if parsed.password else None
    alias = name or f"{kind}-{host}-{database or port}"

    return DatabaseConnectionSpec(
        kind=kind,
        name=alias,
        environment=environment,
        read_only=bool(read_only),
        host=host,
        port=port,
        database=database,
        username=username,
        password=password,
        ssl_mode=ssl_mode,
        reject_unauthorized=reject_unauthorized,
    )


class DatabaseClient:
    """Unified parameterized database client for SQLite, PostgreSQL, MySQL, and Redis."""

    def __init__(
        self,
        target: Union[str, DatabaseConnectionSpec],
        *,
        working_directory: Optional[str] = None,
        read_only: bool = False,
        environment: DbEnvironment = "local",
        name: Optional[str] = None,
    ) -> None:
        if isinstance(target, DatabaseConnectionSpec):
            self.spec = target
        else:
            self.spec = parse_database_target(
                target,
                working_directory=working_directory,
                read_only=read_only,
                environment=environment,
                name=name,
            )
        self._conn: Any = None
        self._pg_flavor: Optional[str] = None

    def __enter__(self) -> "DatabaseClient":
        self.connect()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    def connect(self) -> "DatabaseClient":
        if self._conn is not None:
            return self

        kind = self.spec.kind
        if kind == "sqlite":
            target_path = self.spec.file_path or ":memory:"
            if self.spec.read_only and target_path != ":memory:":
                p = Path(target_path)
                if not p.exists():
                    raise FileNotFoundError(f"SQLite file not found: {target_path}")
                self._conn = sqlite3.connect(f"{p.resolve().as_uri()}?mode=ro", uri=True, timeout=8.0)
            else:
                self._conn = sqlite3.connect(target_path, timeout=8.0)
            self._conn.row_factory = sqlite3.Row
            return self

        if kind == "postgres":
            pg_mod = None
            try:
                pg_mod = importlib.import_module("psycopg")
                self._pg_flavor = "psycopg"
            except ImportError:
                try:
                    pg_mod = importlib.import_module("psycopg2")
                    self._pg_flavor = "psycopg2"
                except ImportError as exc:
                    raise ImportError(
                        "PostgreSQL driver not installed. Install optional dependency: pip install 'wide-sdk[postgres]'"
                    ) from exc

            kwargs: Dict[str, Any] = {
                "host": self.spec.host or "localhost",
                "port": self.spec.port or 5432,
                "dbname": self.spec.database or "postgres",
                "user": self.spec.username,
                "password": self.spec.password,
                "connect_timeout": 8,
            }
            if self.spec.ssl_mode != "default":
                kwargs["sslmode"] = self.spec.ssl_mode
            self._conn = pg_mod.connect(**kwargs)
            return self

        if kind == "mysql":
            try:
                pymysql = importlib.import_module("pymysql")
            except ImportError as exc:
                raise ImportError(
                    "MySQL driver not installed. Install optional dependency: pip install 'wide-sdk[mysql]'"
                ) from exc
            ssl_cfg = {} if self.spec.ssl_mode in ("require", "verify-full") else None
            self._conn = pymysql.connect(
                host=self.spec.host or "localhost",
                port=self.spec.port or 3306,
                user=self.spec.username,
                password=self.spec.password,
                database=self.spec.database or None,
                connect_timeout=8,
                ssl=ssl_cfg,
                cursorclass=pymysql.cursors.DictCursor,
            )
            return self

        try:
            redis_mod = importlib.import_module("redis")
        except ImportError as exc:
            raise ImportError(
                "Redis driver not installed. Install optional dependency: pip install 'wide-sdk[redis]'"
            ) from exc
        self._conn = redis_mod.Redis(
            host=self.spec.host or "localhost",
            port=self.spec.port or 6379,
            username=self.spec.username,
            password=self.spec.password,
            db=int(self.spec.database or 0),
            ssl=self.spec.ssl_mode in ("require", "verify-full"),
            socket_connect_timeout=8,
            decode_responses=True,
        )
        return self

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None

    def _ensure_connected(self) -> Any:
        if self._conn is None:
            self.connect()
        return self._conn

    def _guard_query(self, query: str, allow_destructive: bool) -> None:
        if self.spec.read_only and not is_query_readonly(query, self.spec.kind):
            raise PermissionError(
                f"Connection '{self.spec.name}' is read-only; mutating query is blocked."
            )
        destructive, reason = assess_sql_risk(query, self.spec.kind)
        if destructive and not allow_destructive:
            raise PermissionError(
                f"Blocked destructive query ({reason}). Pass allow_destructive=True after explicit confirmation."
            )

    def query(
        self,
        sql: str,
        params: Optional[Union[Sequence[Any], Dict[str, Any]]] = None,
        *,
        max_rows: int = 500,
        allow_destructive: bool = False,
        redact_secrets: bool = False,
    ) -> QueryResult:
        """Execute a parameterized SQL query (or Redis command) with read-only & destructive safeguards."""
        self._guard_query(sql, allow_destructive=allow_destructive)
        conn = self._ensure_connected()
        start = time.monotonic()

        try:
            if self.spec.kind == "redis":
                parts = shlex.split(sql)
                if not parts:
                    raise ValueError("Redis command cannot be empty.")
                raw = conn.execute_command(*parts)
                if isinstance(raw, (list, tuple, set)):
                    seq = list(raw)
                    truncated = len(seq) > max_rows
                    rows = [{"index": idx, "value": val} for idx, val in enumerate(seq[:max_rows])]
                elif isinstance(raw, dict):
                    truncated = False
                    rows = [{"key": k, "value": v} for k, v in raw.items()]
                else:
                    truncated = False
                    rows = [{"result": raw}]
                cols = list(rows[0].keys()) if rows else []
                return QueryResult(
                    columns=cols,
                    rows=rows,
                    row_count=len(rows),
                    elapsed_ms=int((time.monotonic() - start) * 1000),
                    truncated=truncated,
                )

            cur = conn.cursor()
            try:
                if params is not None:
                    cur.execute(sql, params)
                else:
                    cur.execute(sql)

                if cur.description:
                    columns = [str(col[0]) for col in cur.description]
                    fetched = cur.fetchmany(max_rows + 1)
                    truncated = len(fetched) > max_rows
                    sliced = fetched[:max_rows]
                    rows: List[Dict[str, Any]] = []
                    for r in sliced:
                        if isinstance(r, dict):
                            rows.append({k: r.get(k) for k in columns})
                        elif isinstance(r, sqlite3.Row):
                            rows.append({k: r[k] for k in columns})
                        else:
                            rows.append({columns[i]: r[i] for i in range(len(columns))})
                    if redact_secrets:
                        rows = redact_rows(rows, columns=columns)
                    return QueryResult(
                        columns=columns,
                        rows=rows,
                        row_count=len(rows),
                        elapsed_ms=int((time.monotonic() - start) * 1000),
                        truncated=truncated,
                    )

                if not self.spec.read_only:
                    conn.commit()
                changes = cur.rowcount if cur.rowcount is not None and cur.rowcount >= 0 else 0
                return QueryResult(
                    columns=[],
                    rows=[],
                    row_count=0,
                    changes=changes,
                    elapsed_ms=int((time.monotonic() - start) * 1000),
                )
            finally:
                try:
                    cur.close()
                except Exception:
                    pass
        except Exception as exc:
            msg = mask_dsn(str(exc))
            if type(exc) is Exception:
                raise Exception(msg) from None
            raise type(exc)(msg) from None if isinstance(exc, (PermissionError, ValueError)) else exc

    def execute(
        self,
        sql: str,
        params: Optional[Union[Sequence[Any], Dict[str, Any]]] = None,
        *,
        allow_destructive: bool = False,
    ) -> QueryResult:
        return self.query(sql, params=params, allow_destructive=allow_destructive)

    def inspect_schema(self) -> SchemaResult:
        conn = self._ensure_connected()
        target = self.spec.masked_target()

        if self.spec.kind == "redis":
            info = conn.info("server")
            mem = conn.info("memory")
            dbsize = int(conn.dbsize())
            _, keys = conn.scan(cursor=0, count=50)
            sample_keys = [
                {"key": str(k), "type": str(conn.type(k)), "ttl": int(conn.ttl(k))}
                for k in list(keys)[:30]
            ]
            return SchemaResult(
                kind="redis",
                target=target,
                redis_info={
                    "version": info.get("redis_version"),
                    "used_memory": mem.get("used_memory_human"),
                    "db_size": dbsize,
                    "sample_keys": sample_keys,
                },
            )

        tables: List[SchemaTable] = []
        if self.spec.kind == "sqlite":
            cur = conn.cursor()
            cur.execute(
                "SELECT name, type FROM sqlite_master WHERE type IN ('table', 'view') "
                "AND name NOT LIKE 'sqlite_%' ORDER BY name"
            )
            entries = cur.fetchall()
            for row in entries:
                tname = str(row[0])
                ttype: Literal["table", "view"] = "view" if str(row[1]) == "view" else "table"
                qname = _quote_sql_ident(tname, "sqlite")
                cols_raw = cur.execute(f"PRAGMA table_info({qname})").fetchall()
                fks_raw = cur.execute(f"PRAGMA foreign_key_list({qname})").fetchall()
                row_count: Optional[int] = None
                try:
                    cnt = cur.execute(f"SELECT COUNT(*) FROM {qname}").fetchone()
                    if cnt is not None:
                        row_count = int(cnt[0])
                except Exception:
                    pass
                cols = [
                    SchemaColumn(
                        name=str(c[1]),
                        data_type=str(c[2] or "ANY"),
                        nullable=(c[3] == 0 and int(c[5]) == 0),
                        primary_key=int(c[5]) > 0,
                        default_value=str(c[4]) if c[4] is not None else None,
                    )
                    for c in cols_raw
                ]
                fks = [
                    ForeignKeyInfo(column=str(fk[3]), ref_table=str(fk[2]), ref_column=str(fk[4]))
                    for fk in fks_raw
                ]
                tables.append(SchemaTable(name=tname, table_type=ttype, columns=cols, foreign_keys=fks, row_count=row_count))
            return SchemaResult(kind="sqlite", target=target, tables=tables)

        if self.spec.kind == "postgres":
            t_res = self.query(
                "SELECT table_name, table_type FROM information_schema.tables "
                "WHERE table_schema = 'public' ORDER BY table_name"
            )
            c_res = self.query(
                "SELECT table_name, column_name, data_type, is_nullable, column_default "
                "FROM information_schema.columns WHERE table_schema = 'public' "
                "ORDER BY table_name, ordinal_position"
            )
            pk_res = self.query(
                "SELECT kcu.table_name, kcu.column_name "
                "FROM information_schema.table_constraints tc "
                "JOIN information_schema.key_column_usage kcu "
                "ON tc.constraint_name = kcu.constraint_name AND tc.table_schema = kcu.table_schema "
                "WHERE tc.table_schema = 'public' AND tc.constraint_type = 'PRIMARY KEY'"
            )
            fk_res = self.query(
                "SELECT kcu.table_name, kcu.column_name, ccu.table_name AS ref_table, ccu.column_name AS ref_column "
                "FROM information_schema.table_constraints tc "
                "JOIN information_schema.key_column_usage kcu "
                "ON tc.constraint_name = kcu.constraint_name AND tc.table_schema = kcu.table_schema "
                "JOIN information_schema.constraint_column_usage ccu "
                "ON ccu.constraint_name = tc.constraint_name AND ccu.table_schema = tc.table_schema "
                "WHERE tc.table_schema = 'public' AND tc.constraint_type = 'FOREIGN KEY'"
            )
            pks = {(r["table_name"], r["column_name"]) for r in pk_res.rows}
            for t in t_res.rows:
                tname = str(t["table_name"])
                ttype = "view" if "VIEW" in str(t["table_type"]).upper() else "table"
                cols = [
                    SchemaColumn(
                        name=str(c["column_name"]),
                        data_type=str(c["data_type"]),
                        nullable=c["is_nullable"] == "YES",
                        primary_key=(tname, c["column_name"]) in pks,
                        default_value=str(c["column_default"]) if c["column_default"] is not None else None,
                    )
                    for c in c_res.rows if c["table_name"] == tname
                ]
                fks = [
                    ForeignKeyInfo(column=str(f["column_name"]), ref_table=str(f["ref_table"]), ref_column=str(f["ref_column"]))
                    for f in fk_res.rows if f["table_name"] == tname
                ]
                tables.append(SchemaTable(name=tname, table_type=ttype, columns=cols, foreign_keys=fks))
            return SchemaResult(kind="postgres", target=target, tables=tables)

        db_param = (self.spec.database or None,)
        t_res = self.query(
            "SELECT TABLE_NAME AS table_name, TABLE_TYPE AS table_type "
            "FROM information_schema.TABLES WHERE TABLE_SCHEMA = COALESCE(%s, DATABASE()) ORDER BY TABLE_NAME",
            db_param,
        )
        c_res = self.query(
            "SELECT TABLE_NAME AS table_name, COLUMN_NAME AS column_name, DATA_TYPE AS data_type, "
            "IS_NULLABLE AS is_nullable, COLUMN_KEY AS column_key, COLUMN_DEFAULT AS column_default "
            "FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = COALESCE(%s, DATABASE()) "
            "ORDER BY TABLE_NAME, ORDINAL_POSITION",
            db_param,
        )
        fk_res = self.query(
            "SELECT TABLE_NAME AS table_name, COLUMN_NAME AS column_name, "
            "REFERENCED_TABLE_NAME AS ref_table, REFERENCED_COLUMN_NAME AS ref_column "
            "FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA = COALESCE(%s, DATABASE()) "
            "AND REFERENCED_TABLE_NAME IS NOT NULL",
            db_param,
        )
        for t in t_res.rows:
            tname = str(t["table_name"])
            ttype = "view" if "VIEW" in str(t["table_type"]).upper() else "table"
            cols = [
                SchemaColumn(
                    name=str(c["column_name"]),
                    data_type=str(c["data_type"]),
                    nullable=c["is_nullable"] == "YES",
                    primary_key=c["column_key"] == "PRI",
                    default_value=str(c["column_default"]) if c["column_default"] is not None else None,
                )
                for c in c_res.rows if c["table_name"] == tname
            ]
            fks = [
                ForeignKeyInfo(column=str(f["column_name"]), ref_table=str(f["ref_table"]), ref_column=str(f["ref_column"]))
                for f in fk_res.rows if f["table_name"] == tname
            ]
            tables.append(SchemaTable(name=tname, table_type=ttype, columns=cols, foreign_keys=fks))
        return SchemaResult(kind="mysql", target=target, tables=tables)

    def audit_security(self) -> List[SecurityAuditFinding]:
        findings: List[SecurityAuditFinding] = []
        if self.spec.environment == "prod" and not self.spec.read_only:
            findings.append(SecurityAuditFinding(
                severity="HIGH",
                category="access-control",
                target=self.spec.name,
                message="Production database connection is writable (read_only=False).",
                recommendation="Set read_only=True on production inspection/query connections.",
            ))

        if self.spec.kind != "sqlite":
            if self.spec.ssl_mode == "disable":
                findings.append(SecurityAuditFinding(
                    severity="MEDIUM" if _is_localhost(self.spec.host) else "CRITICAL",
                    category="transport-security",
                    target=f"{self.spec.host}:{self.spec.port}",
                    message="TLS is disabled (sslmode=disable); traffic runs in cleartext.",
                    recommendation="Require TLS with sslmode=verify-full or rediss://.",
                ))
            elif not _is_localhost(self.spec.host) and self.spec.ssl_mode == "default":
                findings.append(SecurityAuditFinding(
                    severity="HIGH",
                    category="transport-security",
                    target=f"{self.spec.host}:{self.spec.port}",
                    message="Remote database connection does not enforce strict TLS certificate verification.",
                    recommendation="Configure sslmode=verify-full with trusted CA certificates.",
                ))
        elif self.spec.file_path and self.spec.file_path != ":memory:" and Path(self.spec.file_path).exists():
            p = Path(self.spec.file_path)
            try:
                header = p.read_bytes()[:15]
                if header == b"SQLite format 3":
                    findings.append(SecurityAuditFinding(
                        severity="INFO",
                        category="storage-encryption",
                        target=str(p),
                        message="SQLite database is unencrypted on disk (standard SQLite format 3 header).",
                        recommendation="Protect files containing sensitive records with disk encryption or SQLCipher.",
                    ))
            except Exception:
                pass

        schema = self.inspect_schema()
        if schema.kind == "redis" and schema.redis_info:
            for item in schema.redis_info.get("sample_keys", []):
                if re.search(r"(session|token|secret|password|auth)", item["key"], re.IGNORECASE) and item["ttl"] == -1:
                    findings.append(SecurityAuditFinding(
                        severity="MEDIUM",
                        category="key-hygiene",
                        target=str(item["key"]),
                        message="Sensitive Redis key has no expiration TTL (ttl=-1).",
                        recommendation="Attach bounded TTLs to session and token cache entries.",
                    ))
            return findings

        pii_summary: List[str] = []
        auth_cols: List[Tuple[str, str]] = []
        for t in schema.tables:
            pii_cols = [c.name for c in t.columns if PII_COLUMN_RE.search(c.name)]
            if pii_cols:
                pii_summary.append(f"{t.name} ({', '.join(pii_cols)})")
            for c in t.columns:
                if re.search(r"(password|passwd|pass_hash|password_hash)", c.name, re.IGNORECASE):
                    auth_cols.append((t.name, c.name))

        if pii_summary:
            findings.append(SecurityAuditFinding(
                severity="INFO",
                category="pii-discovery",
                target=self.spec.name,
                message=f"PII columns discovered across {len(pii_summary)} table(s): {'; '.join(pii_summary[:6])}",
                recommendation="Restrict query roles, encrypt at rest, and redact exports.",
            ))

        for tname, cname in auth_cols[:8]:
            try:
                qt = _quote_sql_ident(tname, self.spec.kind)
                qc = _quote_sql_ident(cname, self.spec.kind)
                res = self.query(f"SELECT {qc} AS val FROM {qt} WHERE {qc} IS NOT NULL LIMIT 20", max_rows=20)
                weak_plain = 0
                weak_md5 = 0
                weak_sha1 = 0
                for row in res.rows:
                    cls = _classify_hash_sample(row.get("val"))
                    if cls == "weak_plain":
                        weak_plain += 1
                    elif cls == "weak_md5":
                        weak_md5 += 1
                    elif cls == "weak_sha1":
                        weak_sha1 += 1
                if weak_plain or weak_md5 or weak_sha1:
                    findings.append(SecurityAuditFinding(
                        severity="CRITICAL",
                        category="weak-credential-storage",
                        target=f"{tname}.{cname}",
                        message=(
                            f"Weak or plaintext credential format sampled in '{tname}.{cname}' "
                            f"(plain={weak_plain}, md5={weak_md5}, sha1={weak_sha1})."
                        ),
                        recommendation="Hash passwords using Argon2id, scrypt, or bcrypt.",
                    ))
            except Exception:
                pass

        return findings
