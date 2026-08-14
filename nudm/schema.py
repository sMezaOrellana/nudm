"""UDM schema knowledge used by the DuckDB translator.

Loads the field dictionary extracted from the official UDM field list
(``udm_fields.csv`` at the project root) so the translator knows each
field's type and whether it is ``repeated``.

Also carries the *grouped fields* mapping documented in the UDM search
reference (e.g. ``ip`` expands to ``principal.ip``, ``target.ip``, ...).
"""
from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path

DEFAULT_CSV = Path(__file__).resolve().parent.parent / "udm_fields.csv"

# Grouped UDM fields, as documented in
# https://docs.cloud.google.com/chronicle/docs/investigation/udm-search#search_grouped_fields
GROUPED_FIELDS: dict[str, tuple[str, ...]] = {
    "domain": (
        "about.administrative_domain", "about.asset.network_domain",
        "network.dns.questions.name", "network.dns_domain",
        "principal.administrative_domain", "principal.asset.network_domain",
        "target.administrative_domain", "target.asset.hostname",
        "target.asset.network_domain", "target.hostname",
    ),
    "email": (
        "intermediary.user.email_addresses", "network.email.from",
        "network.email.to", "principal.user.email_addresses",
        "security_result.about.user.email_addresses", "target.user.email_addresses",
    ),
    "file_path": (
        "principal.file.full_path", "principal.process.file.full_path",
        "principal.process.parent_process.file.full_path", "target.file.full_path",
        "target.process.file.full_path", "target.process.parent_process.file.full_path",
    ),
    "hash": (
        "about.file.md5", "about.file.sha1", "about.file.sha256",
        "principal.process.file.md5", "principal.process.file.sha1",
        "principal.process.file.sha256", "security_result.about.file.sha256",
        "target.file.md5", "target.file.sha1", "target.file.sha256",
        "target.process.file.md5", "target.process.file.sha1",
        "target.process.file.sha256",
    ),
    "hostname": (
        "intermediary.hostname", "observer.hostname", "principal.asset.hostname",
        "principal.hostname", "src.asset.hostname", "src.hostname",
        "target.asset.hostname", "target.hostname",
    ),
    "ip": (
        "intermediary.ip", "observer.ip", "principal.artifact.ip",
        "principal.asset.ip", "principal.ip", "src.artifact.ip", "src.asset.ip",
        "src.ip", "target.artifact.ip", "target.asset.ip", "target.ip",
    ),
    "namespace": ("principal.namespace", "src.namespace", "target.namespace"),
    "process_id": (
        "principal.process.parent_process.pid",
        "principal.process.parent_process.product_specific_process_id",
        "principal.process.pid", "principal.process.product_specific_process_id",
        "target.process.parent_process.pid",
        "target.process.parent_process.product_specific_process_id",
        "target.process.pid", "target.process.product_specific_process_id",
    ),
    "user": (
        "about.user.userid", "observer.user.userid",
        "principal.user.user_display_name", "principal.user.userid",
        "principal.user.windows_sid", "src.user.userid",
        "target.user.user_display_name", "target.user.userid",
        "target.user.windows_sid",
    ),
}


@dataclass(frozen=True)
class FieldInfo:
    path: str
    type: str        # string, int32, bool, google.protobuf.Timestamp, Metadata.EventType, ...
    label: str       # "", "repeated", "optional"
    enum: bool

    @property
    def repeated(self) -> bool:
        return self.label == "repeated"


class UDMSchema:
    """Lookup of UDM field metadata by dotted path (event root)."""

    def __init__(self, csv_path: str | Path = DEFAULT_CSV):
        self._fields: dict[str, FieldInfo] = {}
        path = Path(csv_path)
        if path.exists():
            with path.open(newline="", encoding="utf-8") as fh:
                for row in csv.DictReader(fh):
                    if row["root"] == "event":
                        self._fields[row["path"]] = FieldInfo(
                            path=row["path"], type=row["type"],
                            label=row["label"], enum=row["enum"] == "True",
                        )
                    elif row["root"] == "entity":
                        # graph.* search paths map onto the entity model.
                        self._fields.setdefault(
                            "graph." + row["path"],
                            FieldInfo("graph." + row["path"], row["type"],
                                      row["label"], row["enum"] == "True"),
                        )

    def lookup(self, path: str) -> FieldInfo | None:
        return self._fields.get(path)

    def type_of(self, path: str) -> str:
        info = self._fields.get(path)
        return info.type if info else "string"

    def is_repeated(self, path: str) -> bool:
        info = self._fields.get(path)
        return bool(info and info.repeated)

    def is_numeric(self, path: str) -> bool:
        return self.type_of(path) in {
            "int32", "int64", "uint32", "uint64", "float", "double",
        }

    def is_bool(self, path: str) -> bool:
        return self.type_of(path) == "bool"

    def duckdb_type(self, path: str) -> str:
        """The DuckDB SQL type a UDM field's JSON-extracted value should be
        cast to before comparison. Scalars get their native type; enums
        compare as their string name; message-typed fields (e.g. an
        unindexed ``security_result``) fall back to ``VARCHAR`` since they
        are only ever used bare, as an existence check."""
        info = self._fields.get(path)
        if info is None or info.enum:
            return "VARCHAR"
        return DUCKDB_SCALAR_TYPES.get(info.type, "VARCHAR")


# Proto scalar type -> DuckDB SQL type, for CASTing a JSON-extracted value.
# Anything not listed here (message types, google.protobuf.Struct, etc.)
# falls back to VARCHAR.
DUCKDB_SCALAR_TYPES: dict[str, str] = {
    "string": "VARCHAR",
    "bytes": "VARCHAR",
    "bool": "BOOLEAN",
    "int32": "BIGINT",
    "int64": "BIGINT",
    "uint32": "BIGINT",
    "uint64": "BIGINT",
    "float": "DOUBLE",
    "double": "DOUBLE",
    # Stored/emitted as an ISO 8601 string (protobuf JSON canonical form),
    # which DuckDB casts to TIMESTAMP directly.
    "google.protobuf.Timestamp": "TIMESTAMP",
}
