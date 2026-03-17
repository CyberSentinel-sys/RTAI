"""
core/local_cve_db.py
SQLite-backed local CVE database for air-gapped operation.

The database stores a curated set of CVE records that the AnalystAgent can
query without any internet connectivity.  The database file is created
automatically on first use (default: data/local_cves.db).

Usage
-----
    from core.local_cve_db import LocalCveDatabase

    db = LocalCveDatabase()                      # opens data/local_cves.db
    db.insert_cve("CVE-2021-44228", "Log4Shell RCE", 10.0, "log4j")
    results = db.search_by_product("log4j")
    # [{"cve_id": "CVE-2021-44228", "description": "...", "cvss_score": 10.0,
    #   "affected_product": "log4j"}]
"""
from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
_DEFAULT_DB = _ROOT / "data" / "local_cves.db"

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS cves (
    cve_id           TEXT PRIMARY KEY,
    description      TEXT NOT NULL,
    cvss_score       REAL NOT NULL,
    affected_product TEXT NOT NULL
);
"""


class LocalCveDatabase:
    """
    Lightweight SQLite CVE store for offline/air-gapped engagements.

    Parameters
    ----------
    db_path:
        Path to the SQLite database file.  The parent directory is created
        automatically if it does not exist.  Defaults to ``data/local_cves.db``
        relative to the project root.
    """

    def __init__(self, db_path: Path | str = _DEFAULT_DB) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute(_CREATE_TABLE)
        self._conn.commit()

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def insert_cve(
        self,
        cve_id: str,
        description: str,
        cvss_score: float,
        affected_product: str,
    ) -> None:
        """
        Insert or replace a CVE record.

        Parameters
        ----------
        cve_id:
            Canonical identifier, e.g. ``"CVE-2021-44228"``.
        description:
            Plain-English description of the vulnerability.
        cvss_score:
            CVSS v3 base score (0.0–10.0).
        affected_product:
            Lowercase product / service keyword, e.g. ``"log4j"``.
        """
        self._conn.execute(
            """
            INSERT OR REPLACE INTO cves (cve_id, description, cvss_score, affected_product)
            VALUES (?, ?, ?, ?)
            """,
            (cve_id, description, float(cvss_score), affected_product.lower()),
        )
        self._conn.commit()

    def insert_many(self, records: list[dict[str, Any]]) -> None:
        """
        Bulk-insert a list of CVE record dicts.

        Each dict must have keys: ``cve_id``, ``description``,
        ``cvss_score``, ``affected_product``.
        """
        rows = [
            (r["cve_id"], r["description"], float(r["cvss_score"]), r["affected_product"].lower())
            for r in records
        ]
        self._conn.executemany(
            "INSERT OR REPLACE INTO cves (cve_id, description, cvss_score, affected_product) VALUES (?, ?, ?, ?)",
            rows,
        )
        self._conn.commit()

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def search_by_product(self, product_keyword: str) -> list[dict[str, Any]]:
        """
        Fuzzy-search CVEs whose ``affected_product`` contains *product_keyword*.

        The search is case-insensitive and uses SQL ``LIKE`` with leading and
        trailing wildcards.  Results are returned sorted by ``cvss_score``
        descending (most severe first).

        Parameters
        ----------
        product_keyword:
            Partial product name, e.g. ``"openssh"``, ``"log4j"``,
            ``"apache"``.

        Returns
        -------
        List of dicts with keys ``cve_id``, ``description``,
        ``cvss_score``, ``affected_product``.
        """
        kw = f"%{product_keyword.lower()}%"
        cursor = self._conn.execute(
            """
            SELECT cve_id, description, cvss_score, affected_product
            FROM   cves
            WHERE  affected_product LIKE ?
            ORDER  BY cvss_score DESC
            """,
            (kw,),
        )
        return [dict(row) for row in cursor.fetchall()]

    def count(self) -> int:
        """Return the total number of CVE records stored."""
        return self._conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0]

    def close(self) -> None:
        """Close the underlying database connection."""
        self._conn.close()

    def __enter__(self) -> "LocalCveDatabase":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()
