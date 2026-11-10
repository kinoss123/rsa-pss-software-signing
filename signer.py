"""RSA-PSS / SHA-256 software signing tool.

Companion code for the report on RSA digital signatures for software
integrity verification.

Configuration (matches Section 3.3 of the report):
    - RSA key size: 2048 bits, public exponent e = 65537
    - Scheme: RSASSA-PSS
    - MGF: MGF1 with SHA-256
    - Hash: SHA-256
    - Salt length: 32 bytes

Usage:
    python signer.py keygen  [--out-dir keys]
    python signer.py sign    FILE --key keys/private.pem [--out FILE.sig]
    python signer.py verify  FILE --key keys/public.pem [--sig FILE.sig]
                             [--fingerprint SHA256_HEX]

This is an educational tool. The private key is stored unencrypted on disk,
which is not a production key-management design.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

KEY_SIZE = 2048
PUBLIC_EXPONENT = 65537

HASH = hashes.SHA256()
PSS_PADDING = padding.PSS(
    mgf=padding.MGF1(HASH),
    salt_length=HASH.digest_size,  # 32-byte salt for SHA-256
)


# --------------------------------------------------------------------------
# Core functions
# --------------------------------------------------------------------------
def generate_key_pair() -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """Generate a 2048-bit RSA key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=PUBLIC_EXPONENT, key_size=KEY_SIZE
    )
    return private_key, private_key.public_key()


def sign(data: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
    """Sign the exact bytes of a file using RSA-PSS and SHA-256."""
    return private_key.sign(data, PSS_PADDING, HASH)


def verify(data: bytes, signature: bytes, public_key: rsa.RSAPublicKey) -> bool:
    """Return True for a valid signature, False for an invalid one."""
    try:
        public_key.verify(signature, data, PSS_PADDING, HASH)
        return True
    except InvalidSignature:
        return False


def public_key_fingerprint(public_key: rsa.RSAPublicKey) -> str:
    """SHA-256 fingerprint of the DER-encoded public key (SubjectPublicKeyInfo)."""
    der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = hashes.Hash(hashes.SHA256())
    digest.update(der)
    return digest.finalize().hex()


# --------------------------------------------------------------------------
# Key file helpers
# --------------------------------------------------------------------------
def save_private_key(key: rsa.RSAPrivateKey, path: Path) -> None:
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path.write_bytes(pem)
    try:
        os.chmod(path, 0o600)  # no-op on some Windows setups
    except OSError:
        pass


def save_public_key(key: rsa.RSAPublicKey, path: Path) -> None:
    pem = key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    path.write_bytes(pem)


def load_private_key(path: Path) -> rsa.RSAPrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ValueError(f"{path} is not an RSA private key")
    return key


def load_public_key(path: Path) -> rsa.RSAPublicKey:
    key = serialization.load_pem_public_key(path.read_bytes())
    if not isinstance(key, rsa.RSAPublicKey):
        raise ValueError(f"{path} is not an RSA public key")
    return key


# --------------------------------------------------------------------------
# CLI commands
# --------------------------------------------------------------------------
def cmd_keygen(args: argparse.Namespace) -> int:
    out_dir: Path = args.out_dir
    private_path = out_dir / "private.pem"
    public_path = out_dir / "public.pem"
    if not args.force and (private_path.exists() or public_path.exists()):
        print(
            f"error: key files already exist in {out_dir} (use --force to overwrite)",
            file=sys.stderr,
        )
        return 2

    out_dir.mkdir(parents=True, exist_ok=True)
    private_key, public_key = generate_key_pair()
    save_private_key(private_key, private_path)
    save_public_key(public_key, public_path)

    print(f"Private key: {private_path}  (keep secret)")
    print(f"Public key:  {public_path}")
    print(f"Public key SHA-256 fingerprint: {public_key_fingerprint(public_key)}")
    print("Publish the fingerprint through a channel separate from the download.")
    return 0


def cmd_sign(args: argparse.Namespace) -> int:
    if not args.file.is_file():
        print(f"error: file not found: {args.file}", file=sys.stderr)
        return 2
    private_key = load_private_key(args.key)
    signature = sign(args.file.read_bytes(), private_key)

    sig_path = args.out or args.file.with_name(args.file.name + ".sig")
    sig_path.write_bytes(signature)
    print(f"Signed {args.file} ({args.file.stat().st_size} bytes)")
    print(f"Signature written to {sig_path} ({len(signature)} bytes)")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    if not args.file.is_file():
        print(f"error: file not found: {args.file}", file=sys.stderr)
        return 2
    sig_path = args.sig or args.file.with_name(args.file.name + ".sig")
    if not sig_path.is_file():
        print(f"error: signature not found: {sig_path}", file=sys.stderr)
        return 2

    public_key = load_public_key(args.key)
    fingerprint = public_key_fingerprint(public_key)
    print(f"Public key SHA-256 fingerprint: {fingerprint}")

    if args.fingerprint is not None:
        expected = args.fingerprint.replace(":", "").lower()
        if expected != fingerprint:
            print("INVALID: public key does not match the expected fingerprint")
            return 1

    if verify(args.file.read_bytes(), sig_path.read_bytes(), public_key):
        print(f"VALID: {args.file} matches its signature")
        return 0
    print(f"INVALID: {args.file} does not match its signature")
    return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="RSA-PSS/SHA-256 software signing and verification."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_keygen = sub.add_parser("keygen", help="generate a 2048-bit RSA key pair")
    p_keygen.add_argument("--out-dir", type=Path, default=Path("keys"))
    p_keygen.add_argument("--force", action="store_true", help="overwrite existing keys")
    p_keygen.set_defaults(func=cmd_keygen)

    p_sign = sub.add_parser("sign", help="create a detached signature for a file")
    p_sign.add_argument("file", type=Path)
    p_sign.add_argument("--key", type=Path, required=True, help="private key (PEM)")
    p_sign.add_argument("--out", type=Path, help="signature path (default: FILE.sig)")
    p_sign.set_defaults(func=cmd_sign)

    p_verify = sub.add_parser("verify", help="verify a file against its signature")
    p_verify.add_argument("file", type=Path)
    p_verify.add_argument("--key", type=Path, required=True, help="public key (PEM)")
    p_verify.add_argument("--sig", type=Path, help="signature path (default: FILE.sig)")
    p_verify.add_argument(
        "--fingerprint",
        help="expected SHA-256 fingerprint of the public key, obtained out of band",
    )
    p_verify.set_defaults(func=cmd_verify)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
