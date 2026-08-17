"""Synthetic Git fixtures for finding-source authorization tests."""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import unicodedata
import uuid
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

os.environ.pop("GIT_NO_REPLACE_OBJECTS", None)
os.environ.pop("GIT_REPLACE_REF_BASE", None)

sys.path.insert(0, sys.argv[1])
import workbench_source_excerpt as excerpts
import workbench_source_scopes as scopes
from workbench_target import clean_worktree_content_digest


def git(repository: Path, *arguments: str, input_data: bytes | None = None) -> str:
    environment = dict(
        os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1"
    )
    result = subprocess.run(
        [
            "git",
            "-c",
            "user.name=Example",
            "-c",
            "user.email=example@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "-C",
            str(repository),
            *arguments,
        ],
        input=input_data,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        check=True,
    )
    return result.stdout.decode().strip()


def write(repository: Path, name: str, content: str) -> None:
    path = repository / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def commit(repository: Path) -> str:
    git(repository, "add", "--all")
    git(repository, "commit", "--quiet", "-m", "Synthetic fixture")
    return git(repository, "rev-parse", "HEAD")


def scan(repository: Path, revision: str, paths: list[str]) -> dict:
    identity = (revision, clean_worktree_content_digest(), 0, 0)
    return {
        "target_revision": revision,
        "target_snapshot_digest": identity[1],
        "source_scopes_json": json.dumps(
            scopes.capture_source_scopes(repository, identity, paths)
        ),
        "recipe_json": None,
    }


def excerpt(
    record: dict, repository: Path, path: str, selected: list[str]
) -> str | None:
    return excerpts.finding_source_excerpt(
        record, repository, [{"path": path, "startLine": 1}], selected
    )


def replacements(repository: Path) -> dict:
    write(repository, "selected.py", "selected source\n")
    write(repository, "private.py", "private source\n")
    write(repository, "selected/public.py", "selected directory\n")
    write(repository, "private/public.py", "private directory\n")
    revision = commit(repository)
    file_record = scan(repository, revision, ["selected.py"])
    directory_record = scan(repository, revision, ["selected"])
    file_object = git(repository, "rev-parse", "HEAD:selected.py")
    private_object = git(repository, "rev-parse", "HEAD:private.py")
    tree_object = git(repository, "rev-parse", "HEAD:selected")
    private_tree = git(repository, "rev-parse", "HEAD:private")
    git(repository, "replace", file_object, private_object)
    git(repository, "replace", tree_object, private_tree)
    scopes.tree_entries.cache_clear()
    assert (
        excerpt(file_record, repository, "selected.py", ["selected.py"])
        == "1  selected source"
    )
    assert (
        excerpt(directory_record, repository, "selected/public.py", ["selected"])
        == "1  selected directory"
    )
    scopes.tree_entries.cache_clear()
    captured = scan(repository, revision, ["selected.py", "selected"])
    assert (
        excerpt(captured, repository, "selected.py", ["selected.py", "selected"])
        == "1  selected source"
    )
    assert (
        excerpt(captured, repository, "selected/public.py", ["selected.py", "selected"])
        == "1  selected directory"
    )
    return {"savedObjectsUnchanged": True, "captureIgnoresReplacements": True}


def replacement_snapshot(repository: Path) -> dict:
    from workbench_scan_start import scan_target_identity

    write(repository, "src/public.py", "historical source\n")
    write(repository, "src/removed.py", "historical-only source\n")
    historical = commit(repository)
    write(repository, "src/public.py", "scanned source\n")
    (repository / "src/removed.py").unlink()
    replacement = commit(repository)
    git(repository, "reset", "--hard", historical)
    git(repository, "replace", historical, replacement)
    git(repository, "reset", "--hard", historical)
    assert git(repository, "status", "--porcelain") == ""
    assert not (repository / "src/removed.py").exists()
    identity = scan_target_identity(repository, None)
    assert identity[1] == clean_worktree_content_digest()
    authority = scopes.capture_source_scopes(repository, identity, ["src"])
    assert authority["scopes"] == []
    record = {
        "target_revision": identity[0],
        "target_snapshot_digest": identity[1],
        "source_scopes_json": json.dumps(authority),
        "recipe_json": None,
    }
    assert excerpt(record, repository, "src/removed.py", ["src"]) is None
    legacy = {**record, "source_scopes_json": None}
    assert excerpt(legacy, repository, "src/removed.py", ["."]) is None
    git(repository, "replace", "--delete", historical)
    with patch.dict(
        os.environ, {"GIT_REPLACE_REF_BASE": "refs/synthetic-replacements/"}
    ):
        git(repository, "replace", historical, replacement)
        git(repository, "reset", "--hard", historical)
        assert (
            scopes.capture_source_scopes(
                repository, scan_target_identity(repository, None), ["src"]
            )["scopes"]
            == []
        )
        assert excerpt(legacy, repository, "src/removed.py", ["."]) is None
    return {"mismatchedCaptureOmitted": True, "ambiguousLegacyViewOmitted": True}


def boundaries(repository: Path) -> dict:
    for name, content in {
        "src/public.py": "public source\n",
        "src/support.py": "support source\n",
        "src/nested/child.py": "nested source\n",
        "private/secret.py": "private source\n",
        "selected.py": "selected file\n",
        "other.py": "other file\n",
    }.items():
        write(repository, name, content)
    linked = False
    try:
        (repository / "src/redirected").symlink_to(
            repository / "private", target_is_directory=True
        )
        (repository / "src/escaped").symlink_to(
            repository.parent, target_is_directory=True
        )
        linked = True
    except OSError:
        pass
    revision = commit(repository)
    selected = scan(repository, revision, ["src"])
    single = scan(repository, revision, ["selected.py"])
    multiple = scan(repository, revision, ["src", "selected.py"])
    whole = scan(repository, revision, ["."])
    legacy = {
        "target_revision": revision,
        "target_snapshot_digest": None,
        "recipe_json": None,
    }
    legacy_kinds = {
        **legacy,
        "recipe_json": json.dumps({"_codexSecurityFileScopes": ["selected.py"]}),
    }
    result = {
        "selected": excerpt(selected, repository, "src/public.py", ["src"]),
        "outside": excerpt(selected, repository, "private/secret.py", ["src"]),
        "additional": excerpt(
            multiple, repository, "selected.py", ["src", "selected.py"]
        ),
        "repository": excerpt(whole, repository, "private/secret.py", ["."]),
        "fileDescendant": excerpt(
            single, repository, "selected.py/private.py", ["selected.py"]
        ),
        "traversal": excerpt(selected, repository, "src/../private/secret.py", ["src"]),
        "absolute": excerpt(
            selected, repository, str(repository / "src/public.py"), ["src"]
        ),
        "redirected": excerpt(selected, repository, "src/redirected/secret.py", ["src"])
        if linked
        else None,
        "escaped": excerpt(selected, repository, "src/escaped/secret.py", ["src"])
        if linked
        else None,
        "legacyScoped": excerpt(legacy, repository, "src/public.py", ["src"]),
        "legacyUnmarkedFile": excerpt(
            legacy, repository, "selected.py", ["selected.py"]
        ),
        "legacyUnmarkedFileDescendant": excerpt(
            legacy, repository, "selected.py/private.py", ["selected.py"]
        ),
        "legacyRoot": excerpt(legacy, repository, "private/secret.py", ["."]),
        "legacyKnownDirectory": excerpt(
            legacy_kinds, repository, "src/public.py", ["src"]
        ),
        "legacyKnownFile": excerpt(
            legacy_kinds, repository, "selected.py", ["selected.py"]
        ),
        "legacyFileDescendant": excerpt(
            legacy_kinds, repository, "selected.py/private.py", ["selected.py"]
        ),
        "emptyAuthority": excerpt(
            {
                **selected,
                "source_scopes_json": json.dumps(
                    {"version": 1, "revision": revision, "scopes": []}
                ),
            },
            repository,
            "src/public.py",
            ["src"],
        ),
        "dirty": excerpt(
            {**selected, "target_snapshot_digest": "dirty"},
            repository,
            "src/public.py",
            ["src"],
        ),
        "fallback": excerpts.finding_source_excerpt(
            selected,
            repository,
            [
                {"path": "private/secret.py", "startLine": 1, "role": "root_control"},
                {"path": "src/public.py", "startLine": 1},
            ],
            ["src"],
        ),
        "rootControl": excerpts.finding_source_excerpt(
            selected,
            repository,
            [
                {
                    "path": "src/support.py",
                    "startLine": 1,
                    "role": "evidence:root_control",
                },
                {"path": "src/public.py", "startLine": 1, "role": "root_control"},
            ],
            ["src"],
        ),
    }
    (repository / "selected.py").unlink()
    write(repository, "selected.py/private.py", "replacement private source\n")
    result["replacedFile"] = excerpt(single, repository, "selected.py", ["selected.py"])
    result["replacedFileDescendant"] = excerpt(
        single, repository, "selected.py/private.py", ["selected.py"]
    )
    shutil.rmtree(repository / "src")
    result["removedDirectory"] = excerpt(
        selected, repository, "src/nested/child.py", ["src"]
    )
    calls = []
    original = scopes.git_bytes

    def observed(target: Path, *arguments: str):
        calls.append(
            (
                os.environ.get("GIT_NO_LAZY_FETCH"),
                os.environ.get("GIT_ALLOW_PROTOCOL"),
                os.environ.get("GIT_NO_REPLACE_OBJECTS"),
            )
        )
        return original(target, *arguments)

    with patch.object(scopes, "git_bytes", observed):
        result["offline"] = excerpt(selected, repository, "src/public.py", ["src"])
    assert calls and all(call == ("1", "", "1") for call in calls)
    with patch.object(excerpts, "offline_git_bytes", return_value=None):
        result["missingObject"] = excerpt(
            selected, repository, "src/public.py", ["src"]
        )
    return result


def aliases(repository: Path) -> dict:
    composed = unicodedata.normalize("NFC", "café")
    decomposed = unicodedata.normalize("NFD", composed)
    write(repository, "src/nested/public.py", "historical source\n")
    write(repository, f"{composed}/public.py", "unicode source\n")
    write(repository, "Ä/public.py", "non-ASCII source\n")
    revision = commit(repository)
    git(repository, "config", "core.precomposeunicode", "true")
    cases = [
        ("case", "SRC/NESTED", "src/nested", "historical source"),
        ("unicode", decomposed, composed, "unicode source"),
        ("nonAscii", "ä", "Ä", "non-ASCII source"),
    ]
    result = {}
    for name, requested, canonical, content in cases:
        supported = (repository / requested).exists() and (
            repository / requested
        ).samefile(repository / canonical)
        record = scan(repository, revision, [requested])
        saved = json.loads(record["source_scopes_json"])["scopes"]
        if supported:
            assert len(saved) == 1
            parent = repository / canonical
            moved = repository / f"moved-{name}"
            parent.rename(moved)
            try:
                assert (
                    excerpt(record, repository, f"{canonical}/public.py", [requested])
                    == f"1  {content}"
                )
                assert (
                    excerpt(record, repository, f"{requested}/public.py", [requested])
                    == f"1  {content}"
                )
            finally:
                moved.rename(parent)
        else:
            assert saved == []
        result[name] = supported

    blob = git(
        repository, "hash-object", "-w", "--stdin", input_data=b"colliding source\n"
    )
    git(
        repository,
        "update-index",
        "--add",
        "--cacheinfo",
        f"100644,{blob},SRC/hidden.py",
    )
    tree = git(repository, "write-tree")
    collision_revision = git(
        repository,
        "commit-tree",
        tree,
        "-p",
        revision,
        input_data=b"Synthetic collision\n",
    )
    upper = repository / "SRC"
    distinct = not upper.exists()
    if distinct:
        write(repository, "SRC/hidden.py", "colliding source\n")
    collision = scan(repository, collision_revision, ["src"])
    saved = json.loads(collision["source_scopes_json"])["scopes"]
    assert bool(saved) == distinct
    assert excerpt(collision, repository, "SRC/hidden.py", ["src"]) is None
    legacy_collision = {
        "target_revision": collision_revision,
        "target_snapshot_digest": None,
        "recipe_json": json.dumps({"_codexSecurityFileScopes": []}),
    }
    assert (
        excerpt(legacy_collision, repository, "src/nested/public.py", ["src"]) is None
    )
    if distinct:
        shutil.rmtree(upper)
        missing = scan(repository, collision_revision, ["src"])
        assert json.loads(missing["source_scopes_json"])["scopes"] == []
    result["collisionChecked"] = True
    return result


def alias_evidence(_: Path) -> dict:
    selected, candidate = Path("/synthetic/SECRET.py"), Path("/synthetic/secret.py")
    result = {}
    for kind in ("ordinary", "hardlink", "symlink", "reparse"):
        names = ["SECRET.py", "secret.py"] if kind == "hardlink" else ["SECRET.py"]
        entries = [SimpleNamespace(name=name) for name in names]

        def metadata(path: Path):
            mode = (
                stat.S_IFLNK
                if kind == "symlink" and path == candidate
                else stat.S_IFREG
            )
            return SimpleNamespace(
                st_mode=mode, st_file_attributes=0x400 if kind == "reparse" else 0
            )

        with (
            patch.object(Path, "lstat", metadata),
            patch.object(Path, "samefile", return_value=True),
            patch.object(
                scopes.os, "scandir", side_effect=lambda _: nullcontext(entries)
            ),
            patch.object(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400, create=True),
        ):
            result[kind] = scopes.filesystem_alias(selected, candidate)
    return result


def worktrees(repository: Path) -> dict:
    write(repository, "nested/src/public.py", "nested target source\n")
    write(repository, "private.py", "outside target source\n")
    revision = commit(repository)
    selected = repository / "nested"
    record = scan(selected, revision, ["src"])
    assert (
        excerpt(record, selected, "src/public.py", ["src"]) == "1  nested target source"
    )
    assert excerpt(record, selected, "../private.py", ["src"]) is None
    linked = repository.parent / "linked-worktree"
    git(repository, "worktree", "add", "--quiet", "--detach", str(linked), revision)
    linked_target = linked / "nested"
    assert (
        excerpt(record, linked_target, "src/public.py", ["src"])
        == "1  nested target source"
    )
    linked_record = scan(linked_target, revision, ["."])
    assert (
        excerpt(linked_record, linked_target, "src/public.py", ["."])
        == "1  nested target source"
    )
    assert excerpt(linked_record, linked_target, "private.py", ["."]) is None
    return {"subdirectoryBound": True, "linkedWorktreeBound": True}


def writers(repository: Path) -> dict:
    write(repository, "src/public.py", "public source\n")
    write(repository, "selected.py", "selected file\n")
    revision = commit(repository)
    state = repository.parent / "state"
    scan_root = repository.parent / "scans"
    environment = dict(os.environ, CODEX_SECURITY_STATE_DIR=str(state))
    script = str(Path(sys.argv[1]) / "workbench_db.py")

    def command(*arguments: str, succeeds: bool = True):
        result = subprocess.run(
            [sys.executable, "-I", "-B", script, *arguments],
            env=environment,
            text=True,
            capture_output=True,
        )
        if not succeeds:
            assert result.returncode != 0
            return result.stderr
        assert result.returncode == 0, result.stderr
        return json.loads(result.stdout)

    workspace = str(uuid.uuid4())
    command(
        "create-workspace",
        "--workspace-id",
        workspace,
        "--thread-id",
        "synthetic-workspace",
    )
    command(
        "save-workspace",
        "--workspace-id",
        workspace,
        "--target-path",
        str(repository),
        "--scope",
        "src",
        "--mode",
        "standard",
    )
    command("start-scan", "--workspace-id", workspace, "--scan-root", str(scan_root))
    command(
        "start-prompt-only-scan",
        "--thread-id",
        "synthetic-prompt",
        "--target-path",
        str(repository),
        "--scope",
        "src",
        "--mode",
        "standard",
        "--scan-root",
        str(scan_root),
    )
    command(
        "start-headless-standard-scan",
        "--thread-id",
        "synthetic-headless",
        "--target-path",
        str(repository),
        "--scope",
        "src",
        "--scan-root",
        str(scan_root),
    )
    direct_deep = command(
        "begin-deep-scan",
        "--thread-id",
        "synthetic-direct-deep",
        "--target-path",
        str(repository),
        "--scan-root",
        str(scan_root),
    )["deepScan"]["scanId"]
    cli_directory = Path(tempfile.mkdtemp(prefix="cli-scan-", dir=repository.parent))
    recipe = {
        "config": {},
        "mode": "standard",
        "repository": str(repository),
        "target": {"kind": "paths", "paths": ["src", "selected.py"]},
    }
    registered = command(
        "register-cli-scan",
        "--repository",
        str(repository),
        "--scan-dir",
        str(cli_directory),
        "--recipe-json",
        json.dumps({**recipe, "_codexSecurityFileScopes": ["other.py"]}),
    )
    assert (
        command("get-scan-recipe", "--scan-id", registered["scanId"])["recipe"]
        == recipe
    )
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute("SELECT * FROM scans").fetchall()
        assert len(rows) == 5
        for row in rows:
            metadata = json.loads(row["source_scopes_json"])
            assert metadata["revision"] == revision
            expected = (
                {"src", "selected.py"}
                if row["id"] == registered["scanId"]
                else {"."}
                if row["id"] == direct_deep
                else {"src"}
            )
            assert {scope["path"] for scope in metadata["scopes"]} == expected
            historical = {**dict(row), "source_scopes_json": None}
            assert (
                excerpt(historical, repository, "src/public.py", list(expected))
                == "1  public source"
            )
            if row["id"] == registered["scanId"]:
                assert (
                    excerpt(historical, repository, "selected.py", list(expected))
                    == "1  selected file"
                )
            if row["id"] != registered["scanId"]:
                assert row["recipe_json"] is None
                assert "does not have a saved launch recipe" in command(
                    "get-scan-recipe", "--scan-id", row["id"], succeeds=False
                )
        deep_record = next(row for row in rows if row["id"] == direct_deep)
        git(
            repository,
            "commit",
            "--amend",
            "--quiet",
            "-m",
            "Rewritten synthetic fixture",
        )
        git(repository, "reflog", "expire", "--expire=now", "--all")
        git(repository, "gc", "--prune=now")
        try:
            git(repository, "cat-file", "-e", revision)
        except subprocess.CalledProcessError:
            pass
        else:
            raise AssertionError("Original commit was not pruned")
        assert (
            excerpt(deep_record, repository, "selected.py", ["."]) == "1  selected file"
        )
    return {
        "writers": 5,
        "nativeRecipesUnchanged": True,
        "cliRecipeUnchanged": True,
        "legacyExactScopesPreserved": True,
    }


def migration(_: Path) -> dict:
    from workbench_schema import MIGRATIONS, apply_migrations

    timestamp = "2026-08-01T00:00:00Z"
    historical = tuple(item for item in MIGRATIONS if item[0] <= 30)
    for conflict in (False, True):
        connection = sqlite3.connect(":memory:")
        connection.row_factory = sqlite3.Row
        apply = lambda migrations: apply_migrations(
            connection, migrations, lambda: timestamp, lambda _: None
        )
        apply(historical)
        connection.executemany(
            "INSERT INTO schema_migrations VALUES (?, ?, ?)",
            [
                (number, f"synthetic migration {number}", timestamp)
                for number in (31, 32, 33)
            ],
        )
        connection.execute(
            "INSERT INTO scans (id, workspace_id, target_path, target_revision, scope, mode, scan_dir, status, phase, started_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "synthetic-scan",
                "synthetic-workspace",
                "synthetic-target",
                "synthetic-revision",
                ".",
                "standard",
                "synthetic-output",
                "complete",
                "reporting",
                timestamp,
                timestamp,
                timestamp,
            ),
        )
        if conflict:
            connection.execute(
                "INSERT INTO schema_migrations VALUES (34, ?, ?)",
                ("unrelated migration", timestamp),
            )
        connection.commit()
        before = [
            tuple(row)
            for row in connection.execute(
                "SELECT * FROM schema_migrations ORDER BY version"
            )
        ]
        try:
            apply(MIGRATIONS)
        except SystemExit as error:
            assert conflict and "unsupported source-scope migration history" in str(
                error
            )
            assert [
                tuple(row)
                for row in connection.execute(
                    "SELECT * FROM schema_migrations ORDER BY version"
                )
            ] == before
            assert "source_scopes_json" not in {
                row["name"] for row in connection.execute("PRAGMA table_info(scans)")
            }
        else:
            assert not conflict
            assert (
                connection.execute("SELECT source_scopes_json FROM scans").fetchone()[0]
                is None
            )
            assert [
                tuple(row)
                for row in connection.execute(
                    "SELECT * FROM schema_migrations WHERE version IN (31, 32, 33) ORDER BY version"
                )
            ] == [
                (number, f"synthetic migration {number}", timestamp)
                for number in (31, 32, 33)
            ]
            assert (
                connection.execute(
                    "SELECT name FROM schema_migrations WHERE version=34"
                ).fetchone()[0]
                == "persist authorized source excerpt scopes"
            )
            apply(MIGRATIONS)
        connection.close()
    return {
        "legacyAuthorityUnset": True,
        "otherMigrationsPreserved": True,
        "conflictRejected": True,
    }


with tempfile.TemporaryDirectory(prefix="codex-security-source-scopes-") as temporary:
    repository = Path(temporary).resolve() / "repository"
    repository.mkdir()
    git(repository, "init", "--quiet")
    print(
        json.dumps(
            {
                "boundaries": boundaries,
                "replacements": replacements,
                "replacement_snapshot": replacement_snapshot,
                "aliases": aliases,
                "alias_evidence": alias_evidence,
                "worktrees": worktrees,
                "writers": writers,
                "migration": migration,
            }[sys.argv[2]](repository)
        )
    )
