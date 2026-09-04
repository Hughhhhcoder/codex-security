from __future__ import annotations

import sqlite3
import subprocess
import sys
from pathlib import Path


def test_rejects_same_source_and_destination(tmp_path: Path) -> None:
    source = tmp_path / "source.sqlite3"
    with sqlite3.connect(source) as connection:
        connection.execute("CREATE TABLE sample (value TEXT)")

    result = subprocess.run(
        [
            sys.executable,
            str(Path(__file__).parents[1] / "scripts" / "snapshot_sqlite.py"),
            str(source),
            str(source),
        ],
        capture_output=True,
        check=False,
        text=True,
        timeout=1,
    )

    assert result.returncode != 0
    assert "source and destination must refer to different files" in result.stderr
