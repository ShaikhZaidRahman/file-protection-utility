#!/usr/bin/env bash
# End-to-end verification run on Linux/macOS/WSL.
set -u
cd "$(dirname "$0")/.."
FP="python3 filecrypt.py"
W="$(mktemp -d)"; trap "rm -rf \"$W\"" EXIT
export FILEPROTECT_PASSWORD="S3cure-Passphrase!"
step() { printf "\n\033[1;36m== %s\033[0m\n" "$1"; }

step "1. Create a sensitive sample file"
printf "Account: 4111-1111-1111-1111\nPIN: 4821\nNotes: confidential\n" > "$W/secret.txt"
head -c 3000000 /dev/urandom >> "$W/secret.txt"
ls -l "$W/secret.txt"; sha256sum "$W/secret.txt" | tee "$W/before.sha"

step "2. Encrypt -> secret.txt.enc (AES-256-GCM + PBKDF2)"
$FP encrypt "$W/secret.txt"
ls -l "$W/secret.txt.enc"

step "3. Inspect container metadata (no password needed)"
$FP info "$W/secret.txt.enc"

step "4. Ciphertext does not contain the plaintext"
grep -c "4111-1111" "$W/secret.txt.enc" || echo "no plaintext found in .enc (grep count 0)"
echo "First 48 bytes of .enc (header + start of ciphertext):"; od -An -tx1 -N48 "$W/secret.txt.enc"

step "5. Decrypt with the correct password"
mv "$W/secret.txt" "$W/secret.orig"
$FP decrypt "$W/secret.txt.enc"; echo "exit code: $?"
sha256sum "$W/secret.txt" | tee "$W/after.sha"
[ "$(cut -d" " -f1 "$W/before.sha")" = "$(cut -d" " -f1 "$W/after.sha")" ] \
  && echo "SHA-256 MATCH: decrypted file is identical to the original"

step "6. Wrong password is rejected (MAC verification fails)"
FILEPROTECT_PASSWORD="wrong-password" $FP decrypt "$W/secret.txt.enc" -o "$W/bad.txt"; echo "exit code: $?"
ls "$W/bad.txt" 2>/dev/null || echo "no output file was created"

step "7. Tampered ciphertext is rejected (1 flipped byte)"
cp "$W/secret.txt.enc" "$W/tampered.enc"
python3 - "$W/tampered.enc" <<PY
import sys
p = sys.argv[1]; b = bytearray(open(p, "rb").read()); b[1_500_000] ^= 0x01; open(p, "wb").write(b)
PY
$FP decrypt "$W/tampered.enc" -o "$W/tampered.txt"; echo "exit code: $?"

step "8. Truncated ciphertext is rejected"
head -c 2000000 "$W/secret.txt.enc" > "$W/truncated.enc"
$FP decrypt "$W/truncated.enc" -o "$W/trunc.txt"; echo "exit code: $?"

step "9. Existing output is never overwritten silently"
$FP decrypt "$W/secret.txt.enc"; echo "exit code: $?"
