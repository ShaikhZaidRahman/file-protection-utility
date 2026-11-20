"""Command-line interface for fileprotect."""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path

from . import __version__
from .crypto import (
    DEFAULT_CHUNK_SIZE,
    DEFAULT_ITERATIONS,
    MIN_ITERATIONS,
    TAG_LEN,
    AuthenticationError,
    FileProtectError,
    decrypt_file,
    encrypt_file,
    read_header,
)

ENV_PASSWORD = "FILEPROTECT_PASSWORD"  # noqa: S105 - name of an env var, not a secret

EXIT_OK, EXIT_ERROR, EXIT_AUTH = 0, 1, 3  # argparse itself exits with 2 on usage errors


def _get_password(args: argparse.Namespace, confirm: bool) -> str:
    if args.password_file:
        text = Path(args.password_file).read_text(encoding="utf-8")
        password = text.removesuffix("\n").removesuffix("\r")
    elif ENV_PASSWORD in os.environ:
        password = os.environ[ENV_PASSWORD]
    elif sys.stdin.isatty():
        password = getpass.getpass("Password: ")
        if confirm and getpass.getpass("Confirm password: ") != password:
            raise FileProtectError("Passwords do not match.")
    else:
        raise FileProtectError(
            f"No password available: use --password-file, set {ENV_PASSWORD}, or run interactively."
        )
    if not password:
        raise FileProtectError("Password must not be empty.")
    return password


def _remove_source(path: Path, quiet: bool) -> None:
    path.unlink()
    if not quiet:
        print(f"Removed source file: {path}")


def _cmd_encrypt(args: argparse.Namespace) -> int:
    password = _get_password(args, confirm=True)
    out = encrypt_file(
        args.input,
        args.output,
        password,
        iterations=args.iterations,
        chunk_size=args.chunk_size,
        overwrite=args.force,
    )
    if not args.quiet:
        print(f"Encrypted: {args.input} -> {out}")
    if args.remove_source:
        _remove_source(Path(args.input), args.quiet)
    return EXIT_OK


def _cmd_decrypt(args: argparse.Namespace) -> int:
    password = _get_password(args, confirm=False)
    out = decrypt_file(args.input, args.output, password, overwrite=args.force)
    if not args.quiet:
        print(f"Decrypted: {args.input} -> {out}  [integrity verified]")
    if args.remove_source:
        _remove_source(Path(args.input), args.quiet)
    return EXIT_OK


def _cmd_info(args: argparse.Namespace) -> int:
    path = Path(args.input)
    with open(path, "rb") as fh:
        header = read_header(fh)
    payload = path.stat().st_size - len(header.pack())
    chunks = max(1, -(-payload // (header.chunk_size + TAG_LEN)))
    print(
        f"File:        {path}\n"
        f"Format:      fileprotect v{header.version}\n"
        f"Cipher:      AES-256-GCM (authenticated)\n"
        f"KDF:         PBKDF2-HMAC-SHA256, {header.iterations:,} iterations\n"
        f"Salt:        {header.salt.hex()}\n"
        f"Chunk size:  {header.chunk_size:,} bytes\n"
        f"Chunks:      {chunks:,}\n"
        f"Plaintext:   {max(payload - chunks * TAG_LEN, 0):,} bytes"
    )
    return EXIT_OK


def _iterations(value: str) -> int:
    try:
        n = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("must be an integer") from None
    if n < MIN_ITERATIONS:
        raise argparse.ArgumentTypeError(f"must be at least {MIN_ITERATIONS}")
    return n


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("input", help="path of the input file")
    common.add_argument("-o", "--output", help="output path (default derived from input)")
    common.add_argument("-f", "--force", action="store_true", help="overwrite an existing output file")
    common.add_argument("--password-file", metavar="PATH", help="read the password from a file")
    common.add_argument("--remove-source", action="store_true", help="delete the input after success")
    common.add_argument("-q", "--quiet", action="store_true", help="suppress informational output")

    parser = argparse.ArgumentParser(
        prog="fileprotect",
        description="Encrypt and decrypt files with AES-256-GCM and PBKDF2-HMAC-SHA256.",
        epilog=f"Password sources, in order: --password-file, ${ENV_PASSWORD}, interactive prompt.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True, metavar="{encrypt,decrypt,info}")

    enc = sub.add_parser("encrypt", parents=[common], help="encrypt a file to <name>.enc")
    enc.add_argument(
        "--iterations",
        type=_iterations,
        default=DEFAULT_ITERATIONS,
        help=f"PBKDF2 iterations (default: {DEFAULT_ITERATIONS:,})",
    )
    enc.add_argument(
        "--chunk-size",
        type=int,
        default=DEFAULT_CHUNK_SIZE,
        metavar="BYTES",
        help=f"streaming chunk size (default: {DEFAULT_CHUNK_SIZE})",
    )
    enc.set_defaults(func=_cmd_encrypt)

    dec = sub.add_parser("decrypt", parents=[common], help="decrypt and verify a .enc file")
    dec.set_defaults(func=_cmd_decrypt)

    info = sub.add_parser("info", help="show container metadata (no password needed)")
    info.add_argument("input", help="path of the .enc file")
    info.set_defaults(func=_cmd_info)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except AuthenticationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_AUTH
    except (FileProtectError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        print("\nAborted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
