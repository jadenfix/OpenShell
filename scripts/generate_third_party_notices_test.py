# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).with_name("generate_third_party_notices.py")
_SPEC = importlib.util.spec_from_file_location("generate_third_party_notices", _SCRIPT)
assert _SPEC is not None and _SPEC.loader is not None
notices = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = notices
_SPEC.loader.exec_module(notices)

EXISTING = "existing notices\n"
CARGO_ABOUT_JSON = json.dumps(
    {
        "licenses": [
            {
                "id": "MIT",
                "text": "MIT license text",
                "used_by": [{"crate": {"name": "serde", "version": "1.0.0"}}],
            }
        ]
    }
)
PIP_LICENSES_JSON = json.dumps(
    [{"Name": "grpcio", "Version": "1.0", "License": "Apache-2.0", "LicenseText": ""}]
)


def _fake_run(failing: str, failure: BaseException):
    def run(cmd, **_kwargs):
        if failing in cmd:
            raise failure
        stdout = CARGO_ABOUT_JSON if cmd[0] == "cargo-about" else PIP_LICENSES_JSON
        return subprocess.CompletedProcess(cmd, 0, stdout=stdout, stderr="")

    return run


@pytest.fixture
def repo(tmp_path, monkeypatch):
    (tmp_path / "THIRD-PARTY-NOTICES").write_text(EXISTING)
    monkeypatch.setattr(notices, "find_repo_root", lambda: tmp_path)
    return tmp_path


@pytest.mark.parametrize(
    ("failing", "failure"),
    [
        ("cargo-about", FileNotFoundError("cargo-about")),
        (
            "cargo-about",
            subprocess.CalledProcessError(1, ["cargo-about"], stderr="boom"),
        ),
        ("uv", FileNotFoundError("uv")),
        (
            "pip-licenses",
            subprocess.CalledProcessError(1, ["uv"], stderr="boom"),
        ),
    ],
)
def test_collector_failure_keeps_existing_notices(
    repo, monkeypatch, capsys, failing, failure
):
    monkeypatch.setattr(notices.subprocess, "run", _fake_run(failing, failure))

    assert notices.main() != 0

    assert (repo / "THIRD-PARTY-NOTICES").read_text() == EXISTING
    assert "THIRD-PARTY-NOTICES was not updated" in capsys.readouterr().err


def test_successful_collection_writes_both_sections(repo, monkeypatch):
    monkeypatch.setattr(notices.subprocess, "run", _fake_run("<none>", OSError()))

    assert notices.main() == 0

    written = (repo / "THIRD-PARTY-NOTICES").read_text()
    assert "Rust Dependencies (1 packages)" in written
    assert "Python Dependencies (1 packages)" in written
