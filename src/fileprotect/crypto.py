"""Core cryptographic routines.

Container format (all integers big-endian)::

    offset  size  field
    ------  ----  -----------------------------------------------
    0       4     magic            b"FPU1"
    4       1     version          0x01
    5       4     pbkdf2_iterations
    9       4     chunk_size       plaintext bytes per chunk
    13      16    salt             random, unique per file
    29      7     nonce_prefix     random, unique per file
    36      ...   chunks           AES-256-GCM(ciphertext || 16-byte tag)

Design notes
------------
* Key derivation: PBKDF2-HMAC-SHA256 with a 128-bit random salt -> 256-bit key.
* Cipher: AES-256-GCM (authenticated encryption; the GCM tag is the MAC).
* Large files are processed in fixed-size chunks (constant memory) using the
  STREAM construction: the per-chunk 96-bit nonce is
  ``nonce_prefix(7) || chunk_counter(4) || final_flag(1)``.
  - Reordering or duplicating chunks fails (counter is bound to the nonce).
  - Truncation or appending fails (the last chunk is bound via the final flag).
* The full header is passed as associated data (AAD) for every chunk, so any
  header tampering invalidates authentication.
* Output is written to a temporary file and atomically moved into place only
  after every chunk has been authenticated, so a failed run never leaves
  partial or unauthenticated plaintext at the destination.
"""

from __future__ import annotations

import contextlib
import os
import secrets
import struct
import tempfile
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

MAGIC = b"FPU1"
VERSION = 1
KEY_LEN = 32  # AES-256
SALT_LEN = 16
NONCE_PREFIX_LEN = 7
TAG_LEN = 16

DEFAULT_ITERATIONS = 600_000  # OWASP (2023) guidance for PBKDF2-HMAC-SHA256
MIN_ITERATIONS = 100_000
MAX_ITERATIONS = 100_000_000  # guards against DoS via a crafted header
DEFAULT_CHUNK_SIZE = 1024 * 1024  # 1 MiB
MIN_CHUNK_SIZE = 16
MAX_CHUNK_SIZE = 64 * 1024 * 1024
_MAX_COUNTER = 0xFFFFFFFF

_HEADER = struct.Struct(f">4sBII{SALT_LEN}s{NONCE_PREFIX_LEN}s")
HEADER_LEN = _HEADER.size


class FileProtectError(Exception):
    """Base class for all library errors."""


class InvalidFormatError(FileProtectError):
    """The input is not a valid (or supported) encrypted container."""


class AuthenticationError(FileProtectError):
    """MAC verification failed: wrong password, or the data was modified."""


class OutputExistsError(FileProtectError):
    """The destination exists and overwriting was not requested."""


@dataclass(frozen=True)
class Header:
    iterations: int
    chunk_size: int
    salt: bytes
    nonce_prefix: bytes
    version: int = VERSION

    def pack(self) -> bytes:
        return _HEADER.pack(
            MAGIC, self.version, self.iterations, self.chunk_size, self.salt, self.nonce_prefix
        )

    @classmethod
    def unpack(cls, data: bytes) -> Header:
        if len(data) != HEADER_LEN:
            raise InvalidFormatError("File is too short to be an encrypted container.")
        magic, version, iterations, chunk_size, salt, prefix = _HEADER.unpack(data)
        if magic != MAGIC:
            raise InvalidFormatError("Not a fileprotect container (bad magic bytes).")
        if version != VERSION:
            raise InvalidFormatError(f"Unsupported container version: {version}.")
        _validate_params(iterations, chunk_size)
        return cls(iterations, chunk_size, salt, prefix, version)

    @classmethod
    def new(cls, iterations: int, chunk_size: int) -> Header:
        _validate_params(iterations, chunk_size)
        return cls(
            iterations,
            chunk_size,
            secrets.token_bytes(SALT_LEN),
            secrets.token_bytes(NONCE_PREFIX_LEN),
        )


def _validate_params(iterations: int, chunk_size: int) -> None:
    if not MIN_ITERATIONS <= iterations <= MAX_ITERATIONS:
        raise InvalidFormatError(
            f"PBKDF2 iterations must be within [{MIN_ITERATIONS}, {MAX_ITERATIONS}], got {iterations}."
        )
    if not MIN_CHUNK_SIZE <= chunk_size <= MAX_CHUNK_SIZE:
        raise InvalidFormatError(
            f"Chunk size must be within [{MIN_CHUNK_SIZE}, {MAX_CHUNK_SIZE}], got {chunk_size}."
        )


def derive_key(password: str, salt: bytes, iterations: int = DEFAULT_ITERATIONS) -> bytes:
    """Derive a 256-bit key from *password* using PBKDF2-HMAC-SHA256."""
    if not password:
        raise ValueError("Password must not be empty.")
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=KEY_LEN, salt=salt, iterations=iterations)
    # NFKC normalisation keeps keys identical across platforms/keyboards.
    return kdf.derive(unicodedata.normalize("NFKC", password).encode("utf-8"))


def _nonce(prefix: bytes, counter: int, final: bool) -> bytes:
    if counter > _MAX_COUNTER:
        raise FileProtectError("File too large for the chosen chunk size.")
    return prefix + counter.to_bytes(4, "big") + (b"\x01" if final else b"\x00")


def read_header(src: BinaryIO) -> Header:
    return Header.unpack(src.read(HEADER_LEN))


def encrypt_stream(
    src: BinaryIO,
    dst: BinaryIO,
    password: str,
    *,
    iterations: int = DEFAULT_ITERATIONS,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> int:
    """Encrypt *src* into *dst*. Returns the number of plaintext bytes processed."""
    header = Header.new(iterations, chunk_size)
    aad = header.pack()
    aead = AESGCM(derive_key(password, header.salt, header.iterations))
    dst.write(aad)

    total = 0
    counter = 0
    current = src.read(chunk_size)
    while True:
        upcoming = src.read(chunk_size)  # one-chunk lookahead to detect the final chunk
        final = not upcoming
        dst.write(aead.encrypt(_nonce(header.nonce_prefix, counter, final), current, aad))
        total += len(current)
        if final:
            return total
        current, counter = upcoming, counter + 1


def decrypt_stream(src: BinaryIO, dst: BinaryIO, password: str) -> int:
    """Decrypt *src* into *dst*. Returns the number of plaintext bytes written.

    Raises :class:`AuthenticationError` if any chunk fails MAC verification.
    Note: *dst* may already contain unauthenticated data when this raises; use
    :func:`decrypt_file`, which discards it, for file-based work.
    """
    raw_header = src.read(HEADER_LEN)
    header = Header.unpack(raw_header)
    aead = AESGCM(derive_key(password, header.salt, header.iterations))
    enc_size = header.chunk_size + TAG_LEN

    current = src.read(enc_size)
    if len(current) < TAG_LEN:
        raise InvalidFormatError("Encrypted container is truncated.")

    total = 0
    counter = 0
    while True:
        upcoming = src.read(enc_size)
        final = not upcoming
        try:
            plaintext = aead.decrypt(_nonce(header.nonce_prefix, counter, final), current, raw_header)
        except InvalidTag:
            raise AuthenticationError(
                "Authentication failed: wrong password, or the file is corrupted or has been tampered with."
            ) from None
        dst.write(plaintext)
        total += len(plaintext)
        if final:
            return total
        current, counter = upcoming, counter + 1


@contextlib.contextmanager
def _atomic_output(dest: Path, overwrite: bool):
    """Yield a private temp file next to *dest*; move into place only on success."""
    if dest.is_dir():
        raise FileProtectError(f"Output path is a directory: {dest}")
    if dest.exists() and not overwrite:
        raise OutputExistsError(f"Output file already exists: {dest} (use --force to overwrite).")
    fd, tmp = tempfile.mkstemp(prefix=f".{dest.name}.", suffix=".tmp", dir=dest.parent)  # mode 0600
    try:
        with os.fdopen(fd, "wb") as fh:
            yield fh
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, dest)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def _check_distinct(src: Path, dst: Path) -> None:
    if dst.exists() and src.exists() and os.path.samefile(src, dst):
        raise FileProtectError("Input and output paths refer to the same file.")


def encrypt_file(
    src: str | os.PathLike,
    dst: str | os.PathLike | None,
    password: str,
    *,
    iterations: int = DEFAULT_ITERATIONS,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    overwrite: bool = False,
) -> Path:
    """Encrypt *src* to *dst* (default: ``<src>.enc``) and return the output path."""
    src_p = Path(src)
    dst_p = Path(dst) if dst else src_p.with_name(src_p.name + ".enc")
    _check_distinct(src_p, dst_p)
    with open(src_p, "rb") as fin, _atomic_output(dst_p, overwrite) as fout:
        encrypt_stream(fin, fout, password, iterations=iterations, chunk_size=chunk_size)
    return dst_p


def decrypt_file(
    src: str | os.PathLike,
    dst: str | os.PathLike | None,
    password: str,
    *,
    overwrite: bool = False,
) -> Path:
    """Decrypt *src* to *dst* (default: strip ``.enc``, else append ``.dec``)."""
    src_p = Path(src)
    if dst:
        dst_p = Path(dst)
    elif src_p.suffix == ".enc":
        dst_p = src_p.with_suffix("")
    else:
        dst_p = src_p.with_name(src_p.name + ".dec")
    _check_distinct(src_p, dst_p)
    with open(src_p, "rb") as fin, _atomic_output(dst_p, overwrite) as fout:
        decrypt_stream(fin, fout, password)
    return dst_p
