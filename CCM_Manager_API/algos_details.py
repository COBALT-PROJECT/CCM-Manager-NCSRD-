import json


details = {
    "RSA 2048": {
        "Primitive": "PKE",
        "Functions": [
            "keygen",
            "encrypt",
            "decrypt",
            "sign",
            "verify"
        ],
        "NIST_Security_Category": 1,
        "certification level": "fips140-2-l1"
    },
    "RSA 3072": {
        "Primitive": "PKE",
        "Functions": [
            "keygen",
            "encrypt",
            "decrypt",
            "sign",
            "verify"
        ],
        "NIST_Security_Category": 2,
        "certification level": "fips140-2-l1"
    },
    "RSA 4096": {
        "Primitive": "PKE",
        "Functions": [
            "keygen",
            "encrypt",
            "decrypt",
            "sign",
            "verify"
        ],
        "NIST_Security_Category": 3,
        "certification level": "fips140-2-l1"
    },
    "ECDSA P-192": {
        "Primitive": "Signature",
        "Functions": [
            "keygen",
            "sign",
            "verify"
        ],
        "NIST_Security_Category": 1,
        "certification level": "fips140-2-l1"
    },
    "ECDSA P-224": {
        "Primitive": "Signature",
        "Functions": [
            "keygen",
            "sign",
            "verify"
        ],
        "NIST_Security_Category": 1,
        "certification level": "fips140-2-l1"
    },
    "ECDSA P-256": {
        "Primitive": "Signature",
        "Functions": [
            "keygen",
            "sign",
            "verify"
        ],
        "NIST_Security_Category": 2,
        "certification level": "fips140-2-l1"
    },
    "ECDSA P-384": {
        "Primitive": "Signature",
        "Functions": [
            "keygen",
            "sign",
            "verify"
        ],
        "NIST_Security_Category": 3,
        "certification level": "fips140-2-l1"
    },
    "ECDSA P-521": {
        "Primitive": "Signature",
        "Functions": [
            "keygen",
            "sign",
            "verify"
        ],
        "NIST_Security_Category": 4,
        "certification level": "fips140-2-l1"
    },
    "DSA (1024-bit)": {
        "Primitive": "Signature",
        "Functions": [
            "keygen",
            "sign",
            "verify"
        ],
        "NIST_Security_Category": 0,
        "certification level": "fips140-2-l1"
    },
    "DSA (2048-bit)": {
        "Primitive": "Signature",
        "Functions": [
            "keygen",
            "sign",
            "verify"
        ],
        "NIST_Security_Category": 2,
        "certification level": "fips140-2-l1"
    },
    "AES-128": {
        "Primitive": "Block-cipher",
        "Functions": [
            "keygen",
            "encrypt",
            "decrypt"
        ],
        "NIST_Security_Category": 2,
        "certification level": "fips140-2-l1"
    },
    "AES-192": {
        "Primitive": "Block-cipher",
        "Functions": [
            "keygen",
            "encrypt",
            "decrypt"
        ],
        "NIST_Security_Category": 3,
        "certification level": "fips140-2-l1"
    },
    "AES-256": {
        "Primitive": "Block-cipher",
        "Functions": [
            "keygen",
            "encrypt",
            "decrypt"
        ],
        "NIST_Security_Category": 4,
        "certification level": "fips140-2-l1"
    },
    "ChaCha20": {
        "Primitive": "Stream-cipher",
        "Functions": [
            "keygen",
            "encrypt",
            "decrypt"
        ],
        "NIST_Security_Category": 2,
        "certification level": "none"
    },
    "SHA-1": {
        "Primitive": "Hash",
        "Functions": [
            "digest"
        ],
        "NIST_Security_Category": 0,
        "certification level": "fips140-2-l1"
    },
    "SHA-256": {
        "Primitive": "Hash",
        "Functions": [
            "digest"
        ],
        "NIST_Security_Category": 2,
        "certification level": "fips140-2-l1"
    },
    "SHA-384": {
        "Primitive": "Hash",
        "Functions": [
            "digest"
        ],
        "NIST_Security_Category": 3,
        "certification level": "fips140-2-l1"
    },
    "SHA-512": {
        "Primitive": "Hash",
        "Functions": [
            "digest"
        ],
        "NIST_Security_Category": 4,
        "certification level": "fips140-2-l1"
    },
    "SHA-512/256": {
        "Primitive": "Hash",
        "Functions": [
            "digest"
        ],
        "NIST_Security_Category": 4,
        "certification level": "fips140-2-l1"
    },
    "SHA-3-256": {
        "Primitive": "Hash",
        "Functions": [
            "digest"
        ],
        "NIST_Security_Category": 2,
        "certification level": "fips140-2-l1"
    },
    "SHA-3-384": {
        "Primitive": "Hash",
        "Functions": [
            "digest"
        ],
        "NIST_Security_Category": 3,
        "certification level": "fips140-2-l1"
    },
    "SHA-3-512": {
        "Primitive": "Hash",
        "Functions": [
            "digest"
        ],
        "NIST_Security_Category": 4,
        "certification level": "fips140-2-l1"
    },
    "RSA PKCS1 v1.5": {
        "Primitive": "PKE",
        "Functions": [
            "keygen",
            "encrypt",
            "decrypt",
            "sign",
            "verify"
        ],
        "NIST_Security_Category": 1,
        "certification level": "fips140-2-l1"
    },
    "RSA OAEP": {
        "Primitive": "PKE",
        "Functions": [
            "keygen",
            "encrypt",
            "decrypt"
        ],
        "NIST_Security_Category": 2,
        "certification level": "fips140-2-l1"
    },
    "ECDHE (P-256)": {
        "Primitive": "Key-agree",
        "Functions": [
            "keygen",
            "keyderive"
        ],
        "NIST_Security_Category": 2,
        "certification level": "fips140-2-l1"
    },
    "ECDHE (P-384)": {
        "Primitive": "Key-agree",
        "Functions": [
            "keygen",
            "keyderive"
        ],
        "NIST_Security_Category": 3,
        "certification level": "fips140-2-l1"
    },
    "ECDHE (P-521)": {
        "Primitive": "Key-agree",
        "Functions": [
            "keygen",
            "keyderive"
        ],
        "NIST_Security_Category": 4,
        "certification level": "fips140-2-l1"
    },
    "DH 2048-bit": {
        "Primitive": "Key-agree",
        "Functions": [
            "keygen",
            "keyderive"
        ],
        "NIST_Security_Category": 2,
        "certification level": "fips140-2-l1"
    },
    "DH 3072-bit": {
        "Primitive": "Key-agree",
        "Functions": [
            "keygen",
            "keyderive"
        ],
        "NIST_Security_Category": 2,
        "certification level": "fips140-2-l1"
    },
    "DH 4096-bit": {
        "Primitive": "Key-agree",
        "Functions": [
            "keygen",
            "keyderive"
        ],
        "NIST_Security_Category": 3,
        "certification level": "fips140-2-l1"
    },
    "DH 8192-bit": {
        "Primitive": "Key-agree",
        "Functions": [
            "keygen",
            "keyderive"
        ],
        "NIST_Security_Category": 4,
        "certification level": "fips140-2-l1"
    },
    "X25519 (ECDH)": {
        "Primitive": "Key-agree",
        "Functions": [
            "keygen",
            "keyderive"
        ],
        "NIST_Security_Category": 2,
        "certification level": "none"
    },
    "X448 (ECDH)": {
        "Primitive": "Key-agree",
        "Functions": [
            "keygen",
            "keyderive"
        ],
        "NIST_Security_Category": 3,
        "certification level": "none"
    },
    "TLS 1.0": {
        "Primitive": "Combiner",
        "Functions": [
            "generate",
            "encrypt",
            "decrypt",
            "tag"
        ],
        "NIST_Security_Category": 0,
        "certification level": "none"
    },
    "TLS 1.1": {
        "Primitive": "Combiner",
        "Functions": [
            "generate",
            "encrypt",
            "decrypt",
            "tag"
        ],
        "NIST_Security_Category": 0,
        "certification level": "none"
    },
    "TLS 1.2": {
        "Primitive": "Combiner",
        "Functions": [
            "generate",
            "encrypt",
            "decrypt",
            "tag"
        ],
        "NIST_Security_Category": 2,
        "certification level": "fips140-2-l2"
    },
    "TLS 1.3": {
        "Primitive": "Combiner",
        "Functions": [
            "generate",
            "encrypt",
            "decrypt",
            "tag"
        ],
        "NIST_Security_Category": 2,
        "certification level": "fips140-2-l2"
    },
    "Camellia-128": {
        "Primitive": "Block-cipher",
        "Functions": [
            "keygen",
            "encrypt",
            "decrypt"
        ],
        "NIST_Security_Category": 2,
        "certification level": "none"
    },
    "Camellia-192": {
        "Primitive": "Block-cipher",
        "Functions": [
            "keygen",
            "encrypt",
            "decrypt"
        ],
        "NIST_Security_Category": 3,
        "certification level": "none"
    },
    "Camellia-256": {
        "Primitive": "Block-cipher",
        "Functions": [
            "keygen",
            "encrypt",
            "decrypt"
        ],
        "NIST_Security_Category": 4,
        "certification level": "none"
    },
    "IDEA": {
        "Primitive": "Block-cipher",
        "Functions": [
            "keygen",
            "encrypt",
            "decrypt"
        ],
        "NIST_Security_Category": 1,
        "certification level": "none"
    },
    "SEED": {
        "Primitive": "Block-cipher",
        "Functions": [
            "keygen",
            "encrypt",
            "decrypt"
        ],
        "NIST_Security_Category": 1,
        "certification level": "none"
    },
    "ARIA-128": {
        "Primitive": "Block-cipher",
        "Functions": [
            "keygen",
            "encrypt",
            "decrypt"
        ],
        "NIST_Security_Category": 2,
        "certification level": "none"
    },
    "ARIA-192": {
        "Primitive": "Block-cipher",
        "Functions": [
            "keygen",
            "encrypt",
            "decrypt"
        ],
        "NIST_Security_Category": 3,
        "certification level": "none"
    },
    "ARIA-256": {
        "Primitive": "Block-cipher",
        "Functions": [
            "keygen",
            "encrypt",
            "decrypt"
        ],
        "NIST_Security_Category": 4,
        "certification level": "none"
    },
    "Threefish-256": {
        "Primitive": "Block-cipher",
        "Functions": [
            "keygen",
            "encrypt",
            "decrypt"
        ],
        "NIST_Security_Category": 2,
        "certification level": "none"
    },
    "Threefish-512": {
        "Primitive": "Block-cipher",
        "Functions": [
            "keygen",
            "encrypt",
            "decrypt"
        ],
        "NIST_Security_Category": 3,
        "certification level": "none"
    },
    "Threefish-1024": {
        "Primitive": "Block-cipher",
        "Functions": [
            "keygen",
            "encrypt",
            "decrypt"
        ],
        "NIST_Security_Category": 4,
        "certification level": "none"
    },
    "Blowfish": {
        "Primitive": "Block-cipher",
        "Functions": [
            "keygen",
            "encrypt",
            "decrypt"
        ],
        "NIST_Security_Category": 1,
        "certification level": "none"
    },
    "Twofish": {
        "Primitive": "Block-cipher",
        "Functions": [
            "keygen",
            "encrypt",
            "decrypt"
        ],
        "NIST_Security_Category": 2,
        "certification level": "none"
    },
    "Serpent": {
        "Primitive": "Block-cipher",
        "Functions": [
            "keygen",
            "encrypt",
            "decrypt"
        ],
        "NIST_Security_Category": 2,
        "certification level": "none"
    },
    "RC4": {
        "Primitive": "Stream-cipher",
        "Functions": [
            "keygen",
            "encrypt",
            "decrypt"
        ],
        "NIST_Security_Category": 0,
        "certification level": "none"
    },
    "RC5": {
        "Primitive": "Block-cipher",
        "Functions": [
            "keygen",
            "encrypt",
            "decrypt"
        ],
        "NIST_Security_Category": 1,
        "certification level": "none"
    },
    "RC6": {
        "Primitive": "Block-cipher",
        "Functions": [
            "keygen",
            "encrypt",
            "decrypt"
        ],
        "NIST_Security_Category": 1,
        "certification level": "none"
    },
    "SHAKE128": {
        "Primitive": "XOF",
        "Functions": [
            "digest"
        ],
        "NIST_Security_Category": 1,
        "certification level": "fips140-2-l1"
    },
    "SHAKE256": {
        "Primitive": "XOF",
        "Functions": [
            "digest"
        ],
        "NIST_Security_Category": 2,
        "certification level": "fips140-2-l2"
    },
    "PBKDF2": {
        "Primitive": "KDF",
        "Functions": [
            "keyderive"
        ],
        "NIST_Security_Category": 1,
        "certification level": "fips140-2-l1"
    },
    "HKDF": {
        "Primitive": "KDF",
        "Functions": [
            "keyderive"
        ],
        "NIST_Security_Category": 1,
        "certification level": "fips140-2-l1"
    },
    "bcrypt": {
        "Primitive": "KDF",
        "Functions": [
            "keyderive"
        ],
        "NIST_Security_Category": 1,
        "certification level": "none"
    },
    "scrypt": {
        "Primitive": "KDF",
        "Functions": [
            "keyderive"
        ],
        "NIST_Security_Category": 2,
        "certification level": "none"
    },
    "Argon2": {
        "Primitive": "KDF",
        "Functions": [
            "keyderive"
        ],
        "NIST_Security_Category": 3,
        "certification level": "none"
    },
    "AES-GCM": {
        "Primitive": "AE",
        "Functions": [
            "keygen",
            "encrypt",
            "decrypt",
            "tag"
        ],
        "NIST_Security_Category": 2,
        "certification level": "fips140-2-l2"
    },
    "AES-CCM": {
        "Primitive": "AE",
        "Functions": [
            "keygen",
            "encrypt",
            "decrypt",
            "tag"
        ],
        "NIST_Security_Category": 2,
        "certification level": "fips140-2-l2"
    },
    "AES-EAX": {
        "Primitive": "AE",
        "Functions": [
            "keygen",
            "encrypt",
            "decrypt",
            "tag"
        ],
        "NIST_Security_Category": 2,
        "certification level": "none"
    },
    "AES-SIV": {
        "Primitive": "AE",
        "Functions": [
            "keygen",
            "encrypt",
            "decrypt",
            "tag"
        ],
        "NIST_Security_Category": 2,
        "certification level": "none"
    },
    "RSA-KEM": {
        "Primitive": "KEM",
        "Functions": [
            "keygen",
            "encapsulate",
            "decapsulate"
        ],
        "NIST_Security_Category": 2,
        "certification level": "none"
    },
    "FrodoKEM": {
        "Primitive": "KEM",
        "Functions": [
            "keygen",
            "encapsulate",
            "decapsulate"
        ],
        "NIST_Security_Category": 3,
        "certification level": "none"
    },
    "Kyber": {
        "Primitive": "KEM",
        "Functions": [
            "keygen",
            "encapsulate",
            "decapsulate"
        ],
        "NIST_Security_Category": 4,
        "certification level": "fips140-3-l1"
    },
    "Dilithium": {
        "Primitive": "Signature",
        "Functions": [
            "keygen",
            "sign",
            "verify"
        ],
        "NIST_Security_Category": 4,
        "certification level": "fips140-3-l1"
    },
    "Falcon": {
        "Primitive": "Signature",
        "Functions": [
            "keygen",
            "sign",
            "verify"
        ],
        "NIST_Security_Category": 4,
        "certification level": "fips140-3-l1"
    },
    "Sphincs+": {
        "Primitive": "Signature",
        "Functions": [
            "keygen",
            "sign",
            "verify"
        ],
        "NIST_Security_Category": 5,
        "certification level": "fips140-3-l1"
    }
}

resources = [
  {
    "Algorithm": "RSA 2048",
    "Classic Security Level": "112 bits",
    "NIST Quantum Security Level": "128 bits",
    "NIST Documentation Reference": "SP 800-57, SP 800-131A"
  },
  {
    "Algorithm": "RSA 3072",
    "Classic Security Level": "128 bits",
    "NIST Quantum Security Level": "192 bits",
    "NIST Documentation Reference": "SP 800-57, SP 800-131A"
  },
  {
    "Algorithm": "RSA 4096",
    "Classic Security Level": "136 bits",
    "NIST Quantum Security Level": "256 bits",
    "NIST Documentation Reference": "SP 800-57, SP 800-131A"
  },
  {
    "Algorithm": "ECDSA P-192",
    "Classic Security Level": "112 bits",
    "NIST Quantum Security Level": "128 bits",
    "NIST Documentation Reference": "SP 800-57, FIPS 186-4"
  },
  {
    "Algorithm": "ECDSA P-224",
    "Classic Security Level": "112 bits",
    "NIST Quantum Security Level": "128 bits",
    "NIST Documentation Reference": "SP 800-57, FIPS 186-4"
  },
  {
    "Algorithm": "ECDSA P-256",
    "Classic Security Level": "128 bits",
    "NIST Quantum Security Level": "192 bits",
    "NIST Documentation Reference": "SP 800-57, FIPS 186-4"
  },
  {
    "Algorithm": "ECDSA P-384",
    "Classic Security Level": "192 bits",
    "NIST Quantum Security Level": "256 bits",
    "NIST Documentation Reference": "SP 800-57, FIPS 186-4"
  },
  {
    "Algorithm": "ECDSA P-521",
    "Classic Security Level": "256 bits",
    "NIST Quantum Security Level": "256 bits",
    "NIST Documentation Reference": "SP 800-57, FIPS 186-4"
  },
  {
    "Algorithm": "DSA (1024-bit)",
    "Classic Security Level": "112 bits",
    "NIST Quantum Security Level": "128 bits",
    "NIST Documentation Reference": "SP 800-57, FIPS 186-4"
  },
  {
    "Algorithm": "DSA (2048-bit)",
    "Classic Security Level": "128 bits",
    "NIST Quantum Security Level": "192 bits",
    "NIST Documentation Reference": "SP 800-57, FIPS 186-4"
  },
  {
    "Algorithm": "AES-128",
    "Classic Security Level": "128 bits",
    "NIST Quantum Security Level": "128 bits",
    "NIST Documentation Reference": "SP 800-57, SP 800-131A"
  },
  {
    "Algorithm": "AES-192",
    "Classic Security Level": "192 bits",
    "NIST Quantum Security Level": "192 bits",
    "NIST Documentation Reference": "SP 800-57, SP 800-131A"
  },
  {
    "Algorithm": "AES-256",
    "Classic Security Level": "256 bits",
    "NIST Quantum Security Level": "256 bits",
    "NIST Documentation Reference": "SP 800-57, SP 800-131A"
  },
  {
    "Algorithm": "ChaCha20",
    "Classic Security Level": "128 bits",
    "NIST Quantum Security Level": "128 bits",
    "NIST Documentation Reference": "SP 800-57"
  },
  {
    "Algorithm": "SHA-1",
    "Classic Security Level": "80 bits",
    "NIST Quantum Security Level": "128 bits",
    "NIST Documentation Reference": "SP 800-57, FIPS 180-4"
  },
  {
    "Algorithm": "SHA-256",
    "Classic Security Level": "128 bits",
    "NIST Quantum Security Level": "192 bits",
    "NIST Documentation Reference": "SP 800-57, FIPS 180-4"
  },
  {
    "Algorithm": "SHA-384",
    "Classic Security Level": "192 bits",
    "NIST Quantum Security Level": "256 bits",
    "NIST Documentation Reference": "SP 800-57, FIPS 180-4"
  },
  {
    "Algorithm": "SHA-512",
    "Classic Security Level": "256 bits",
    "NIST Quantum Security Level": "256 bits",
    "NIST Documentation Reference": "SP 800-57, FIPS 180-4"
  },
  {
    "Algorithm": "SHA-512/256",
    "Classic Security Level": "256 bits",
    "NIST Quantum Security Level": "256 bits",
    "NIST Documentation Reference": "SP 800-57, FIPS 180-4"
  },
  {
    "Algorithm": "SHA-3-256",
    "Classic Security Level": "128 bits",
    "NIST Quantum Security Level": "192 bits",
    "NIST Documentation Reference": "SP 800-185"
  },
  {
    "Algorithm": "SHA-3-384",
    "Classic Security Level": "192 bits",
    "NIST Quantum Security Level": "256 bits",
    "NIST Documentation Reference": "SP 800-185"
  },
  {
    "Algorithm": "SHA-3-512",
    "Classic Security Level": "256 bits",
    "NIST Quantum Security Level": "256 bits",
    "NIST Documentation Reference": "SP 800-185"
  },
  {
    "Algorithm": "RSA PKCS1 v1.5",
    "Classic Security Level": "112 bits",
    "NIST Quantum Security Level": "128 bits",
    "NIST Documentation Reference": "SP 800-57, SP 800-131A"
  },
  {
    "Algorithm": "RSA OAEP",
    "Classic Security Level": "128 bits",
    "NIST Quantum Security Level": "192 bits",
    "NIST Documentation Reference": "SP 800-57, SP 800-131A"
  },
  {
    "Algorithm": "ECDHE (P-256)",
    "Classic Security Level": "128 bits",
    "NIST Quantum Security Level": "192 bits",
    "NIST Documentation Reference": "SP 800-57, FIPS 186-4"
  },
  {
    "Algorithm": "ECDHE (P-384)",
    "Classic Security Level": "192 bits",
    "NIST Quantum Security Level": "256 bits",
    "NIST Documentation Reference": "SP 800-57, FIPS 186-4"
  },
  {
    "Algorithm": "ECDHE (P-521)",
    "Classic Security Level": "256 bits",
    "NIST Quantum Security Level": "256 bits",
    "NIST Documentation Reference": "SP 800-57, FIPS 186-4"
  },
  {
    "Algorithm": "DH 2048-bit",
    "Classic Security Level": "128 bits",
    "NIST Quantum Security Level": "192 bits",
    "NIST Documentation Reference": "SP 800-57, FIPS 186-4"
  },
  {
    "Algorithm": "DH 3072-bit",
    "Classic Security Level": "128 bits",
    "NIST Quantum Security Level": "256 bits",
    "NIST Documentation Reference": "SP 800-57, FIPS 186-4"
  },
  {
    "Algorithm": "DH 4096-bit",
    "Classic Security Level": "160 bits",
    "NIST Quantum Security Level": "256 bits",
    "NIST Documentation Reference": "SP 800-57, FIPS 186-4"
  },
  {
    "Algorithm": "DH 8192-bit",
    "Classic Security Level": "192 bits",
    "NIST Quantum Security Level": "256 bits",
    "NIST Documentation Reference": "SP 800-57, FIPS 186-4"
  },
  {
    "Algorithm": "X25519 (ECDH)",
    "Classic Security Level": "128 bits",
    "NIST Quantum Security Level": "128 bits",
    "NIST Documentation Reference": "SP 800-57, FIPS 186-4"
  },
  {
    "Algorithm": "X448 (ECDH)",
    "Classic Security Level": "192 bits",
    "NIST Quantum Security Level": "192 bits",
    "NIST Documentation Reference": "SP 800-57, FIPS 186-4"
  },
  {
    "Algorithm": "TLS 1.0",
    "Classic Security Level": "80 bits",
    "NIST Quantum Security Level": "128 bits",
    "NIST Documentation Reference": "SP 800-57, FIPS 140-2"
  },
  {
    "Algorithm": "TLS 1.1",
    "Classic Security Level": "112 bits",
    "NIST Quantum Security Level": "128 bits",
    "NIST Documentation Reference": "SP 800-57, FIPS 140-2"
  },
  {
    "Algorithm": "TLS 1.2",
    "Classic Security Level": "128 bits",
    "NIST Quantum Security Level": "192 bits",
    "NIST Documentation Reference": "SP 800-57, FIPS 140-2"
  },
  {
    "Algorithm": "TLS 1.3",
    "Classic Security Level": "128 bits",
    "NIST Quantum Security Level": "192 bits",
    "NIST Documentation Reference": "SP 800-57, FIPS 140-2"
  },
  {
    "Algorithm": "Camellia-128",
    "Classic Security Level": "128 bits",
    "NIST Quantum Security Level": "128 bits",
    "NIST Documentation Reference": "SP 800-57"
  },
  {
    "Algorithm": "Camellia-192",
    "Classic Security Level": "192 bits",
    "NIST Quantum Security Level": "192 bits",
    "NIST Documentation Reference": "SP 800-57"
  },
  {
    "Algorithm": "Camellia-256",
    "Classic Security Level": "256 bits",
    "NIST Quantum Security Level": "256 bits",
    "NIST Documentation Reference": "SP 800-57"
  },
  {
    "Algorithm": "IDEA",
    "Classic Security Level": "128 bits",
    "NIST Quantum Security Level": "128 bits",
    "NIST Documentation Reference": "SP 800-57"
  },
  {
    "Algorithm": "SEED",
    "Classic Security Level": "128 bits",
    "NIST Quantum Security Level": "128 bits",
    "NIST Documentation Reference": "SP 800-57"
  },
  {
    "Algorithm": "ARIA",
    "Classic Security Level": "128 bits",
    "NIST Quantum Security Level": "128 bits",
    "NIST Documentation Reference": "SP 800-57"
  }
]

