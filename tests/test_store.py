"""Exercises AgeStore against a real ``age`` binary in a temp directory."""

from __future__ import annotations

import asyncio
import subprocess
from pathlib import Path

import pytest

from passage_mcp.config import Config
from passage_mcp.store import (
    AgeStore,
    ConflictError,
    ForbiddenError,
    InvalidNameError,
    NotFoundError,
)


def run(coro):
    return asyncio.run(coro)


@pytest.fixture
def store(tmp_path: Path) -> AgeStore:
    identity = tmp_path / "identity"
    subprocess.run(["age-keygen", "-o", str(identity)], check=True, capture_output=True)
    pub = subprocess.run(
        ["age-keygen", "-y", str(identity)], check=True, capture_output=True, text=True
    ).stdout.strip()
    recovery = tmp_path / "recovery"
    subprocess.run(["age-keygen", "-o", str(recovery)], check=True, capture_output=True)
    rpub = subprocess.run(
        ["age-keygen", "-y", str(recovery)], check=True, capture_output=True, text=True
    ).stdout.strip()

    root = tmp_path / "store"
    root.mkdir()
    (root / ".age-recipients").write_text(f"# server\n{pub}\n# recovery\n{rpub}\n")
    (root / "llm").mkdir()
    (root / "infra").mkdir()

    s = AgeStore(Config(store_dir=root, identity_file=identity, allowed_folders=["llm"]))
    run(s.validate())
    return s


def test_validate_auto_allows_existing_folders(store: AgeStore):
    assert store._allowed == ["llm", "infra"]


def test_add_get_edit_roundtrip(store: AgeStore):
    run(store.add_secret("llm", "OPENAI_API_KEY", "sk-1\nline2"))
    assert run(store.get_secret("llm", "OPENAI_API_KEY")) == "sk-1\nline2"
    assert run(store.get_login("llm", "OPENAI_API_KEY")) == {"password": "sk-1\nline2", "username": ""}

    run(store.edit_secret("llm", "OPENAI_API_KEY", "sk-2"))
    assert run(store.get_secret("llm", "OPENAI_API_KEY")) == "sk-2"

    with pytest.raises(ConflictError):
        run(store.add_secret("llm", "OPENAI_API_KEY", "x"))


def test_login_keeps_username_on_edit(store: AgeStore):
    run(store.add_login("infra", "Ubiquiti UniFi SSO", "yeowool@example.com", "pw"))
    run(store.edit_secret("infra", "Ubiquiti UniFi SSO", "pw2"))
    assert run(store.get_login("infra", "Ubiquiti UniFi SSO")) == {
        "password": "pw2",
        "username": "yeowool@example.com",
    }


def test_listing_and_search(store: AgeStore):
    run(store.add_secret("llm", "B_KEY", "1"))
    run(store.add_secret("llm", "A_KEY", "2"))
    run(store.add_secret("infra", "CF_TOKEN", "3"))
    assert run(store.list_secrets("llm")) == [{"folder": "llm", "items": [{"name": "A_KEY"}, {"name": "B_KEY"}]}]
    assert run(store.list_secrets()) == [
        {"folder": "infra", "items": [{"name": "CF_TOKEN"}]},
        {"folder": "llm", "items": [{"name": "A_KEY"}, {"name": "B_KEY"}]},
    ]
    assert run(store.list_secrets("nope")) == []
    assert run(store.list_folders()) == [{"name": "infra"}, {"name": "llm"}]
    assert run(store.search_secrets("key")) == [
        {"folder": "llm", "item_name": "A_KEY"},
        {"folder": "llm", "item_name": "B_KEY"},
    ]


def test_trash_roundtrip(store: AgeStore):
    run(store.add_secret("llm", "K", "v1"))
    run(store.delete_secret("llm", "K"))
    with pytest.raises(NotFoundError):
        run(store.get_secret("llm", "K"))
    trash = run(store.list_trash())
    assert [(t["folder"], t["name"]) for t in trash] == [("llm", "K")]

    # deleting a second item with the same name keeps the first trashed copy
    run(store.add_secret("llm", "K", "v2"))
    run(store.delete_secret("llm", "K"))
    assert len(run(store.list_trash())) == 2

    run(store.recover_secret("llm", "K"))
    assert run(store.get_secret("llm", "K")) == "v2"
    run(store.empty_trash())
    assert run(store.list_trash()) == []


def test_move_rename_folders(store: AgeStore):
    run(store.add_secret("llm", "K", "v"))
    run(store.move_secret("llm", "K", "infra"))
    assert run(store.get_secret("infra", "K")) == "v"
    run(store.rename_secret("infra", "K", "K2"))
    assert run(store.get_secret("infra", "K2")) == "v"

    run(store.add_folder("new"))
    assert "new" in store._allowed
    with pytest.raises(ConflictError):
        run(store.delete_folder("infra"))
    run(store.rename_folder("new", "newer"))
    assert "newer" in store._allowed and "new" not in store._allowed
    # trashed entries follow their folder through a rename
    run(store.add_secret("infra", "T", "v"))
    run(store.delete_secret("infra", "T"))
    run(store.rename_folder("infra", "infra2"))
    assert [(t["folder"], t["name"]) for t in run(store.list_trash())] == [("infra2", "T")]
    run(store.recover_secret("infra2", "T"))
    assert run(store.get_secret("infra2", "T")) == "v"
    run(store.rename_folder("infra2", "infra"))
    run(store.delete_folder("newer"))
    assert run(store.list_folders()) == [{"name": "infra"}, {"name": "llm"}]


def test_forbidden_and_missing(store: AgeStore):
    store._allowed = ["llm"]
    with pytest.raises(ForbiddenError):
        run(store.get_secret("infra", "x"))
    with pytest.raises(NotFoundError):
        run(store.get_secret("llm", "missing"))
    with pytest.raises(ForbiddenError):
        run(store.add_secret("ghost", "x", "y"))
    store._allowed = None
    with pytest.raises(NotFoundError):
        run(store.add_secret("ghost", "x", "y"))


@pytest.mark.parametrize("bad", ["", "../etc", "a/b", ".hidden", "a\x00b", "x" * 201])
def test_invalid_names_rejected(store: AgeStore, bad: str):
    with pytest.raises(InvalidNameError):
        run(store.add_secret("llm", bad, "v"))
    with pytest.raises(InvalidNameError):
        run(store.add_folder(bad))


def test_reads_plain_passage_entry(store: AgeStore):
    """An entry written by `passage insert` (not JSON) is read as the whole secret."""
    target = store._root / "llm" / "manual.age"
    subprocess.run(
        ["age", "-e", "-R", str(store._recipients), "-o", str(target)],
        input=b"hunter2\n", check=True,
    )
    assert run(store.get_login("llm", "manual")) == {"password": "hunter2", "username": ""}
