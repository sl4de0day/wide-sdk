import json
from dataclasses import asdict
from typing import Any, Dict, Literal
from ..database import DatabaseClient, DbEnvironment, mask_dsn
from ..types import ToolDefinition, ToolResult
from .base import BaseTool


def _inspect_schema_handler(params: Dict[str, Any], context: Dict[str, Any]) -> ToolResult:
    target = str(params.get("target") or "").strip()
    if not target:
        return ToolResult(success=False, output="", error="target database URI or SQLite path is required.")
    working_dir = context.get("working_directory")
    try:
        with DatabaseClient(target, working_directory=working_dir, read_only=True) as db:
            schema = db.inspect_schema()
        return ToolResult(success=True, output=json.dumps(asdict(schema), indent=2, default=str))
    except Exception as exc:
        return ToolResult(success=False, output="", error=mask_dsn(str(exc)))


db_inspect_schema_tool = BaseTool(
    definition=ToolDefinition(
        name="db_inspect_schema",
        description="Inspect database tables, columns, primary keys, and foreign keys for a SQLite file or database URI.",
        parameters={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "SQLite file path or database URI."},
            },
            "required": ["target"],
        },
    ),
    handler=_inspect_schema_handler,
)


def _db_query_handler(params: Dict[str, Any], context: Dict[str, Any]) -> ToolResult:
    target = str(params.get("target") or "").strip()
    sql = str(params.get("sql") or "").strip()
    if not target or not sql:
        return ToolResult(success=False, output="", error="Both target and sql are required.")
    working_dir = context.get("working_directory")
    max_rows = max(1, min(500, int(params.get("maxRows") or 200)))
    query_params = params.get("params")
    try:
        with DatabaseClient(target, working_directory=working_dir, read_only=True) as db:
            result = db.query(sql, params=query_params, max_rows=max_rows, redact_secrets=True)
        return ToolResult(success=True, output=json.dumps(asdict(result), indent=2, default=str))
    except Exception as exc:
        return ToolResult(success=False, output="", error=mask_dsn(str(exc)))


db_query_tool = BaseTool(
    definition=ToolDefinition(
        name="db_query",
        description="Execute a read-only parameterized SQL or Redis query. Secret columns are redacted automatically.",
        parameters={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "SQLite file path or database URI."},
                "sql": {"type": "string", "description": "Read-only SQL statement or Redis command."},
                "params": {"type": "array", "description": "Optional bind parameters."},
                "maxRows": {"type": "number", "description": "Maximum rows to return (default 200)."},
            },
            "required": ["target", "sql"],
        },
    ),
    handler=_db_query_handler,
)


def _db_audit_handler(params: Dict[str, Any], context: Dict[str, Any]) -> ToolResult:
    target = str(params.get("target") or "").strip()
    if not target:
        return ToolResult(success=False, output="", error="target database URI or SQLite path is required.")
    working_dir = context.get("working_directory")
    raw_env = str(params.get("environment") or "local")
    env: DbEnvironment = raw_env if raw_env in ("local", "staging", "prod") else "local"
    try:
        with DatabaseClient(target, working_directory=working_dir, read_only=True, environment=env) as db:
            findings = db.audit_security()
        return ToolResult(
            success=True,
            output=json.dumps([asdict(f) for f in findings], indent=2, default=str),
        )
    except Exception as exc:
        return ToolResult(success=False, output="", error=mask_dsn(str(exc)))


db_audit_tool = BaseTool(
    definition=ToolDefinition(
        name="db_audit",
        description="Audit a database connection or SQLite file for PII columns, weak password hashes, and TLS posture.",
        parameters={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "SQLite file path or database URI."},
                "environment": {"type": "string", "description": "Environment label.", "enum": ["local", "staging", "prod"]},
            },
            "required": ["target"],
        },
    ),
    handler=_db_audit_handler,
)


def _db_export_handler(params: Dict[str, Any], context: Dict[str, Any]) -> ToolResult:
    target = str(params.get("target") or "").strip()
    sql = str(params.get("sql") or "").strip()
    raw_fmt = str(params.get("format") or "csv").lower()
    if not target or not sql:
        return ToolResult(success=False, output="", error="Both target and sql are required.")
    if raw_fmt not in ("csv", "json", "sql"):
        return ToolResult(success=False, output="", error="format must be csv, json, or sql.")
    fmt: Literal["csv", "json", "sql"] = raw_fmt
    table_name = str(params.get("tableName") or "query_result").strip() or "query_result"
    max_rows = max(1, min(5000, int(params.get("maxRows") or 1000)))
    working_dir = context.get("working_directory")
    try:
        with DatabaseClient(target, working_directory=working_dir, read_only=True) as db:
            content = db.export_query(sql, fmt=fmt, table_name=table_name, max_rows=max_rows, redact_secrets=True)
        return ToolResult(success=True, output=content)
    except Exception as exc:
        return ToolResult(success=False, output="", error=mask_dsn(str(exc)))


db_export_tool = BaseTool(
    definition=ToolDefinition(
        name="db_export",
        description="Export rows from a read-only SQL query to CSV, JSON, or SQL INSERT format with secret column redaction.",
        parameters={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "SQLite file path or database URI."},
                "sql": {"type": "string", "description": "Read-only SELECT SQL statement."},
                "format": {"type": "string", "description": "Output format: csv, json, or sql.", "enum": ["csv", "json", "sql"]},
                "tableName": {"type": "string", "description": "Table name used for SQL INSERT output."},
                "maxRows": {"type": "number", "description": "Maximum rows to export (default 1000, max 5000)."},
            },
            "required": ["target", "sql", "format"],
        },
    ),
    handler=_db_export_handler,
)
