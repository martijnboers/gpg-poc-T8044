# GnuPG Stack Buffer Overflow PoC

This is what happens if you want to find out if you can vibe-code a missing poc for a CVE.

```
Token Usage: 161740 / 1048576
Input tokens: 24,626
Output tokens: 137,114
Total tokens: 161,740
Cost Estimation *
Input token cost: $0.049252
Output token cost: $1.645368
Total cost: $1.694620
```

This Docker container reproduces a stack buffer overflow in `gpg-agent` (v2.5.16) when processing malformed S/MIME messages (ECC-KEM).

## Files
- `poc_gen.py`: Generates the malformed ASN.1 payload (S/MIME).
- `reproduction.sh`: Automates KeyGen, Exploit Gen, and runs the agent under GDB to capture the crash.
- `Dockerfile`: Compiles the vulnerable GnuPG version from source.

## Usage

### 1. Build the Image
```bash
docker build -t gpg-poc .
docker run --rm -it --privileged gpg-poc ./reproduction.sh
