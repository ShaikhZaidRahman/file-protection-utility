import os

import pytest

from fileprotect.cli import ENV_PASSWORD, main
from fileprotect.crypto import MIN_ITERATIONS

FAST = ["--iterations", str(MIN_ITERATIONS)]


@pytest.fixture(autouse=True)
def _password(monkeypatch):
    monkeypatch.setenv(ENV_PASSWORD, "hunter2-but-longer")


def test_roundtrip_via_cli(tmp_path, capsys):
    src = tmp_path / "secret.txt"
    src.write_bytes(b"top secret " * 1000)
    assert main(["encrypt", str(src), *FAST]) == 0
    enc = tmp_path / "secret.txt.enc"
    assert enc.exists() and b"top secret" not in enc.read_bytes()

    original = src.read_bytes()
    src.unlink()
    assert main(["decrypt", str(enc)]) == 0
    assert src.read_bytes() == original
    assert "integrity verified" in capsys.readouterr().out


def test_wrong_password_exit_code_3(tmp_path, monkeypatch, capsys):
    src = tmp_path / "f"
    src.write_bytes(b"x")
    main(["encrypt", str(src), *FAST])
    monkeypatch.setenv(ENV_PASSWORD, "nope")
    assert main(["decrypt", str(tmp_path / "f.enc"), "-o", str(tmp_path / "out")]) == 3
    assert "Authentication failed" in capsys.readouterr().err
    assert not (tmp_path / "out").exists()


def test_tampered_file_exit_code_3(tmp_path):
    src = tmp_path / "f"
    src.write_bytes(os.urandom(5000))
    main(["encrypt", str(src), *FAST])
    enc = tmp_path / "f.enc"
    blob = bytearray(enc.read_bytes())
    blob[100] ^= 0xFF
    enc.write_bytes(bytes(blob))
    assert main(["decrypt", str(enc), "-o", str(tmp_path / "out")]) == 3


def test_password_file_beats_env(tmp_path, monkeypatch):
    pw = tmp_path / "pw"
    pw.write_text("from-file\n")
    src = tmp_path / "f"
    src.write_bytes(b"x")
    main(["encrypt", str(src), *FAST, "--password-file", str(pw)])
    monkeypatch.delenv(ENV_PASSWORD)
    args = ["decrypt", str(tmp_path / "f.enc"), "-o", str(tmp_path / "o"), "--password-file", str(pw)]
    assert main(args) == 0


def test_no_password_non_interactive(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv(ENV_PASSWORD)
    monkeypatch.setattr("sys.stdin.isatty", lambda: False, raising=False)
    src = tmp_path / "f"
    src.write_bytes(b"x")
    assert main(["encrypt", str(src)]) == 1
    assert "No password available" in capsys.readouterr().err


def test_missing_file_and_existing_output(tmp_path, capsys):
    assert main(["encrypt", str(tmp_path / "missing")]) == 1
    src = tmp_path / "f"
    src.write_bytes(b"x")
    main(["encrypt", str(src), *FAST])
    assert main(["encrypt", str(src), *FAST]) == 1  # exists, no --force
    assert main(["encrypt", str(src), *FAST, "--force"]) == 0


def test_remove_source_and_quiet(tmp_path, capsys):
    src = tmp_path / "f"
    src.write_bytes(b"x")
    assert main(["encrypt", str(src), *FAST, "--remove-source", "-q"]) == 0
    assert not src.exists() and capsys.readouterr().out == ""


def test_info_command(tmp_path, capsys):
    src = tmp_path / "f"
    src.write_bytes(b"x" * 100)
    main(["encrypt", str(src), *FAST, "--chunk-size", "64"])
    capsys.readouterr()
    assert main(["info", str(tmp_path / "f.enc")]) == 0
    out = capsys.readouterr().out
    assert "AES-256-GCM" in out and "PBKDF2-HMAC-SHA256" in out and "100 bytes" in out


def test_info_on_non_container(tmp_path, capsys):
    f = tmp_path / "plain"
    f.write_bytes(b"hello" * 20)
    assert main(["info", str(f)]) == 1


def test_usage_errors():
    with pytest.raises(SystemExit) as e:
        main(["encrypt", "x", "--iterations", "5"])
    assert e.value.code == 2
    with pytest.raises(SystemExit) as e:
        main([])
    assert e.value.code == 2
