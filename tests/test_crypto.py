import io
import os

import pytest

from fileprotect import crypto
from fileprotect.crypto import (
    HEADER_LEN,
    MIN_ITERATIONS,
    TAG_LEN,
    AuthenticationError,
    FileProtectError,
    InvalidFormatError,
    OutputExistsError,
    decrypt_file,
    decrypt_stream,
    derive_key,
    encrypt_file,
    encrypt_stream,
)

PW = "correct horse battery staple"
CHUNK = 64
FAST = {"iterations": MIN_ITERATIONS, "chunk_size": CHUNK}


def _enc(data: bytes, password: str = PW, **kw) -> bytes:
    out = io.BytesIO()
    encrypt_stream(io.BytesIO(data), out, password, **{**FAST, **kw})
    return out.getvalue()


def _dec(blob: bytes, password: str = PW) -> bytes:
    out = io.BytesIO()
    decrypt_stream(io.BytesIO(blob), out, password)
    return out.getvalue()


def _write(path, data):
    path.write_bytes(data)
    return path


@pytest.mark.parametrize("size", [0, 1, CHUNK - 1, CHUNK, CHUNK + 1, 5 * CHUNK, 5 * CHUNK + 7])
def test_roundtrip_sizes(size):
    data = os.urandom(size)
    blob = _enc(data)
    assert _dec(blob) == data


def test_unicode_password_is_normalised():
    blob = _enc(b"data", password="caf\u00e9")  # precomposed
    assert _dec(blob, password="cafe\u0301") == b"data"  # decomposed


def test_key_derivation_matches_reference_pbkdf2():
    import hashlib

    salt = b"salt" * 4
    assert derive_key("password", salt, 100_000) == hashlib.pbkdf2_hmac(
        "sha256", b"password", salt, 100_000, 32
    )


def test_output_is_randomised_and_hides_plaintext():
    data = b"A" * 200
    a, b = _enc(data), _enc(data)
    assert a != b  # fresh salt + nonce prefix
    assert data[:32] not in a
    assert len(a) == HEADER_LEN + len(data) + TAG_LEN * 4  # 200 bytes -> 4 chunks of <=64


def test_wrong_password_fails():
    with pytest.raises(AuthenticationError):
        _dec(_enc(b"secret"), password="wrong")


@pytest.mark.parametrize("where", ["header_salt", "header_iters", "first_chunk", "last_tag"])
def test_bit_flip_detected(where):
    blob = bytearray(_enc(os.urandom(3 * CHUNK)))
    offsets = {"header_salt": 20, "header_iters": 8, "first_chunk": HEADER_LEN + 3, "last_tag": len(blob) - 1}
    blob[offsets[where]] ^= 0x01
    with pytest.raises(FileProtectError):  # salt/iters change => auth error or invalid params
        _dec(bytes(blob))


def test_truncation_at_chunk_boundary_detected():
    blob = _enc(os.urandom(3 * CHUNK))
    with pytest.raises(AuthenticationError):
        _dec(blob[: HEADER_LEN + 2 * (CHUNK + TAG_LEN)])


def test_truncated_mid_chunk_detected():
    with pytest.raises(AuthenticationError):
        _dec(_enc(os.urandom(3 * CHUNK))[:-5])


def test_appended_data_detected():
    blob = _enc(os.urandom(2 * CHUNK))
    with pytest.raises(AuthenticationError):
        _dec(blob + os.urandom(TAG_LEN + 4))


def test_chunk_reordering_detected():
    blob = _enc(os.urandom(4 * CHUNK))
    size = CHUNK + TAG_LEN
    c = [blob[HEADER_LEN + i * size : HEADER_LEN + (i + 1) * size] for i in range(4)]
    c[0], c[1] = c[1], c[0]
    with pytest.raises(AuthenticationError):
        _dec(blob[:HEADER_LEN] + b"".join(c) + blob[HEADER_LEN + 4 * size :])


@pytest.mark.parametrize(
    "blob",
    [b"", b"short", b"XXXX" + b"\x00" * 60, b"FPU1\x09" + b"\x00" * 60],
)
def test_invalid_container(blob):
    with pytest.raises(InvalidFormatError):
        _dec(blob)


def test_header_only_is_truncated():
    with pytest.raises(InvalidFormatError):
        _dec(_enc(b"x")[:HEADER_LEN])


def test_hostile_header_parameters_rejected():
    blob = bytearray(_enc(b"x"))
    blob[5:9] = (2**32 - 1).to_bytes(4, "big")  # absurd iteration count
    with pytest.raises(InvalidFormatError):
        _dec(bytes(blob))


def test_parameter_validation():
    with pytest.raises(InvalidFormatError):
        _enc(b"x", iterations=1000)
    with pytest.raises(ValueError):
        _enc(b"x", password="")


# --- file level -------------------------------------------------------------


def test_file_roundtrip_and_default_names(tmp_path):
    src = tmp_path / "doc.txt"
    src.write_bytes(os.urandom(1000))
    enc = encrypt_file(src, None, PW, **FAST)
    assert enc == tmp_path / "doc.txt.enc"
    src_copy = src.read_bytes()
    src.unlink()
    assert decrypt_file(enc, None, PW) == src
    assert src.read_bytes() == src_copy


def test_default_decrypt_name_without_enc_suffix(tmp_path):
    src = tmp_path / "a.bin"
    src.write_bytes(b"x")
    blob = encrypt_file(src, tmp_path / "a.dat", PW, **FAST)
    assert decrypt_file(blob, None, PW) == tmp_path / "a.dat.dec"


def test_refuses_overwrite_unless_forced(tmp_path):
    src = tmp_path / "f"
    src.write_bytes(b"x")
    out = tmp_path / "f.enc"
    out.write_bytes(b"old")
    with pytest.raises(OutputExistsError):
        encrypt_file(src, out, PW, **FAST)
    assert out.read_bytes() == b"old"
    encrypt_file(src, out, PW, overwrite=True, **FAST)
    assert out.read_bytes() != b"old"


def test_failed_decrypt_leaves_no_output_or_temp_files(tmp_path):
    src = tmp_path / "f"
    src.write_bytes(os.urandom(5 * CHUNK))
    enc = encrypt_file(src, None, PW, **FAST)
    src.unlink()
    with pytest.raises(AuthenticationError):
        decrypt_file(enc, None, "bad")
    assert sorted(p.name for p in tmp_path.iterdir()) == ["f.enc"]


def test_failed_decrypt_does_not_clobber_existing_file(tmp_path):
    enc = encrypt_file(_write(tmp_path / "f", b"data"), None, PW, **FAST)
    target = _write(tmp_path / "keep", b"precious")
    with pytest.raises(AuthenticationError):
        decrypt_file(enc, target, "bad", overwrite=True)
    assert target.read_bytes() == b"precious"


def test_same_file_rejected(tmp_path):
    f = _write(tmp_path / "f", b"x")
    with pytest.raises(FileProtectError):
        encrypt_file(f, f, PW, overwrite=True, **FAST)


def test_directory_output_rejected(tmp_path):
    f = _write(tmp_path / "f", b"x")
    with pytest.raises(FileProtectError):
        encrypt_file(f, tmp_path, PW, overwrite=True, **FAST)


def test_missing_input(tmp_path):
    with pytest.raises(FileNotFoundError):
        encrypt_file(tmp_path / "nope", None, PW, **FAST)


@pytest.mark.skipif(os.name == "nt", reason="POSIX permissions")
def test_output_permissions_are_private(tmp_path):
    enc = encrypt_file(_write(tmp_path / "f", b"x"), None, PW, **FAST)
    assert enc.stat().st_mode & 0o077 == 0


def test_nonce_layout():
    assert crypto._nonce(b"P" * 7, 1, True) == b"P" * 7 + b"\x00\x00\x00\x01\x01"
    with pytest.raises(FileProtectError):
        crypto._nonce(b"P" * 7, 2**32, False)
