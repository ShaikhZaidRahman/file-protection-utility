"""fileprotect - AES-256-GCM file encryption with PBKDF2-HMAC-SHA256 key derivation."""

from .crypto import (
    DEFAULT_CHUNK_SIZE,
    DEFAULT_ITERATIONS,
    AuthenticationError,
    FileProtectError,
    Header,
    InvalidFormatError,
    OutputExistsError,
    decrypt_file,
    decrypt_stream,
    derive_key,
    encrypt_file,
    encrypt_stream,
    read_header,
)

__version__ = "1.0.0"

__all__ = [
    "DEFAULT_CHUNK_SIZE",
    "DEFAULT_ITERATIONS",
    "AuthenticationError",
    "FileProtectError",
    "Header",
    "InvalidFormatError",
    "OutputExistsError",
    "__version__",
    "decrypt_file",
    "decrypt_stream",
    "derive_key",
    "encrypt_file",
    "encrypt_stream",
    "read_header",
]
