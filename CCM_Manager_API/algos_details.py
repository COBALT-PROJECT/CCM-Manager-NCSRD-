details = {
  "AES": {
    "cbc": {
      "128": {
        "Classic Security Level": "128",
        "Functions": [
          "keygen",
          "encrypt",
          "decrypt"
        ],
        "NIST_Security_Category": 2,
        "Primitive": "Block-cipher",
        "certification level": "fips140-2-l1",
        "Mode": "CBC"
      },
      "192": {
        "Classic Security Level": "192",
        "Functions": [
          "keygen",
          "encrypt",
          "decrypt"
        ],
        "NIST_Security_Category": 3,
        "Primitive": "Block-cipher",
        "certification level": "fips140-2-l1",
        "Mode": "CBC"
      },
      "256": {
        "Classic Security Level": "256",
        "Functions": [
          "keygen",
          "encrypt",
          "decrypt"
        ],
        "NIST_Security_Category": 4,
        "Primitive": "Block-cipher",
        "certification level": "fips140-2-l1",
        "Mode": "CBC"
      }
    },
    "gcm": {
      "128": {
        "Classic Security Level": "128",
        "Functions": [
          "keygen",
          "encrypt",
          "decrypt",
          "authenticate"
        ],
        "NIST_Security_Category": 3,
        "Primitive": "Authenticated Encryption",
        "certification level": "fips140-2-l1",
        "Mode": "GCM"
      },
      "256": {
        "Classic Security Level": "256",
        "Functions": [
          "keygen",
          "encrypt",
          "decrypt",
          "authenticate"
        ],
        "NIST_Security_Category": 4,
        "Primitive": "Authenticated Encryption",
        "certification level": "fips140-2-l1",
        "Mode": "GCM"
      }
    }
  },
  "ARIA": {
    "cbc": {
      "128": {
        "Classic Security Level": "128",
        "Functions": [
          "keygen",
          "encrypt",
          "decrypt"
        ],
        "NIST_Security_Category": 2,
        "Primitive": "Block-cipher",
        "certification level": "fips140-2-l1",
        "Mode": "CBC"
      },
      "192": {
        "Classic Security Level": "192",
        "Functions": [
          "keygen",
          "encrypt",
          "decrypt"
        ],
        "NIST_Security_Category": 3,
        "Primitive": "Block-cipher",
        "certification level": "fips140-2-l1",
        "Mode": "CBC"
      },
      "256": {
        "Classic Security Level": "256",
        "Functions": [
          "keygen",
          "encrypt",
          "decrypt"
        ],
        "NIST_Security_Category": 4,
        "Primitive": "Block-cipher",
        "certification level": "fips140-2-l1",
        "Mode": "CBC"
      }
    },
    "other": {
      "128": {
        "Classic Security Level": "128",
        "Functions": [
          "keygen",
          "encrypt",
          "decrypt"
        ],
        "NIST_Security_Category": 2,
        "Primitive": "Block-cipher",
        "certification level": "fips140-2-l1",
        "Mode": "CBC"
      },
      "192": {
        "Classic Security Level": "192",
        "Functions": [
          "keygen",
          "encrypt",
          "decrypt"
        ],
        "NIST_Security_Category": 3,
        "Primitive": "Block-cipher",
        "certification level": "fips140-2-l1",
        "Mode": "CBC"
      },
      "256": {
        "Classic Security Level": "256",
        "Functions": [
          "keygen",
          "encrypt",
          "decrypt"
        ],
        "NIST_Security_Category": 4,
        "Primitive": "Block-cipher",
        "certification level": "fips140-2-l1",
        "Mode": "CBC"
      }
    }
  },
  "Argon2": {
    "Classic Security Level": "unknow",
    "Functions": [
        "keyderive"
    ],
    "NIST_Security_Category": 3,
    "Primitive": "KDF",
    "certification level": "none",
    "Mode": "none"
  },
  "bcrypt": {
    "Classic Security Level": "128",
    "Functions": [
      "keygen",
      "hashing"
    ],
    "NIST_Security_Category": 2,
    "Primitive": "Key Derivation Function",
    "certification level": "not certified",
    "Mode": "none"
  },
  "Blowfish": {
    "cbc": {
      "128": {
        "Classic Security Level": "128",
        "Functions": [
          "keygen",
          "encrypt",
          "decrypt"
        ],
        "NIST_Security_Category": 2,
        "Primitive": "Block-cipher",
        "certification level": "not certified",
        "Mode": "CBC"
      }
    }
  },
  "Camellia": {
    "cbc": {
      "128": {
        "Classic Security Level": "128",
        "Functions": [
          "keygen",
          "encrypt",
          "decrypt"
        ],
        "NIST_Security_Category": 2,
        "Primitive": "Block-cipher",
        "certification level": "fips140-2-l1",
        "Mode": "CBC"
      },
      "192": {
        "Classic Security Level": "192",
        "Functions": [
          "keygen",
          "encrypt",
          "decrypt"
        ],
        "NIST_Security_Category": 3,
        "Primitive": "Block-cipher",
        "certification level": "fips140-2-l1",
        "Mode": "CBC"
      },
      "256": {
        "Classic Security Level": "256",
        "Functions": [
          "keygen",
          "encrypt",
          "decrypt"
        ],
        "NIST_Security_Category": 4,
        "Primitive": "Block-cipher",
        "certification level": "fips140-2-l1",
        "Mode": "CBC"
      }
    }
  },
  "ChaCha20": {
    "Classic Security Level": "128",
    "Functions": [
      "keygen",
      "encrypt",
      "decrypt"
    ],
    "NIST_Security_Category": 2,
    "Primitive": "Stream-cipher",
    "certification level": "not certified",
    "Mode": "none"
  },
  "DH": {
    "Classic Security Level": "2048",
    "Functions": [
      "keygen",
      "key agreement"
    ],
    "NIST_Security_Category": 4,
    "Primitive": "Key agreement",
    "certification level": "fips140-2-l1",
    "Mode": "none"
  },
  "DSA": {
    "Classic Security Level": "2048",
    "Functions": [
      "keygen",
      "sign",
      "verify"
    ],
    "NIST_Security_Category": 4,
    "Primitive": "Signature",
    "certification level": "fips140-2-l1",
    "Mode": "none"
  },
  "Dilithium": {
    "Classic Security Level": "256",
    "Functions": [
      "keygen",
      "sign",
      "verify"
    ],
    "NIST_Security_Category": 5,
    "Primitive": "Signature",
    "certification level": "not certified",
    "Mode": "none"
  },
  "ECDHE": {
    "Classic Security Level": "224",
    "Functions": [
      "keygen",
      "key agreement"
    ],
    "NIST_Security_Category": 3,
    "Primitive": "Key agreement",
    "certification level": "not certified",
    "Mode": "none"
  },
  "ECDSA": {
    "Classic Security Level": "224",
    "Functions": [
      "keygen",
      "sign",
      "verify"
    ],
    "NIST_Security_Category": 3,
    "Primitive": "Signature",
    "certification level": "fips140-2-l1",
    "Mode": "none"
  },
  "Falcon": {
    "Classic Security Level": "256",
    "Functions": [
      "keygen",
      "sign",
      "verify"
    ],
    "NIST_Security_Category": 5,
    "Primitive": "Signature",
    "certification level": "not certified",
    "Mode": "none"
  },
  "FrodoKEM": {
    "Classic Security Level": "128",
    "Functions": [
      "keygen",
      "key encapsulation"
    ],
    "NIST_Security_Category": 5,
    "Primitive": "Key encapsulation",
    "certification level": "not certified",
    "Mode": "none"
  },
  "HKDF": {
    "Classic Security Level": "128",
    "Functions": [
      "keygen",
      "hashing"
    ],
    "NIST_Security_Category": 2,
    "Primitive": "Key Derivation Function",
    "certification level": "not certified",
    "Mode": "none"
  },
  "IDEA": {
    "Classic Security Level": "128",
    "Functions": [
      "keygen",
      "encrypt",
      "decrypt"
    ],
    "NIST_Security_Category": 2,
    "Primitive": "Block-cipher",
    "certification level": "not certified",
    "Mode": "none"
  },
  "Kyber": {
    "Classic Security Level": "256",
    "Functions": [
      "keygen",
      "key encapsulation"
    ],
    "NIST_Security_Category": 5,
    "Primitive": "Key encapsulation",
    "certification level": "not certified",
    "Mode": "none"
  },
  "PBKDF2": {
    "Classic Security Level": "128",
    "Functions": [
      "keygen",
      "hashing"
    ],
    "NIST_Security_Category": 2,
    "Primitive": "Key Derivation Function",
    "certification level": "not certified",
    "Mode": "none"
  },
  "RC4": {
    "Classic Security Level": "128",
    "Functions": [
      "keygen",
      "encrypt",
      "decrypt"
    ],
    "NIST_Security_Category": 1,
    "Primitive": "Stream-cipher",
    "certification level": "not certified",
    "Mode": "none"
  },
  "RC5": {
    "Classic Security Level": "128",
    "Functions": [
      "keygen",
      "encrypt",
      "decrypt"
    ],
    "NIST_Security_Category": 2,
    "Primitive": "Block-cipher",
    "certification level": "not certified",
    "Mode": "none"
  },
  "RC6": {
    "Classic Security Level": "128",
    "Functions": [
      "keygen",
      "encrypt",
      "decrypt"
    ],
    "NIST_Security_Category": 2,
    "Primitive": "Block-cipher",
    "certification level": "not certified",
    "Mode": "none"
  },
  "RSA": {
    "Classic Security Level": "2048",
    "Functions": [
      "keygen",
      "encrypt",
      "decrypt",
      "sign",
      "verify"
    ],
    "NIST_Security_Category": 4,
    "Primitive": "Public-key encryption",
    "certification level": "fips140-2-l1",
    "Mode": "none"
  },
  "SEED": {
    "Classic Security Level": "128",
    "Functions": [
      "keygen",
      "encrypt",
      "decrypt"
    ],
    "NIST_Security_Category": 2,
    "Primitive": "Block-cipher",
    "certification level": "not certified",
    "Mode": "none"
  },
  "SHA": {
    "Classic Security Level": "256",
    "Functions": [
      "hashing"
    ],
    "NIST_Security_Category": 2,
    "Primitive": "Hash function",
    "certification level": "fips140-2-l1",
    "Mode": "none"
  },
  "SHAKE": {
    "Classic Security Level": "256",
    "Functions": [
      "hashing"
    ],
    "NIST_Security_Category": 2,
    "Primitive": "Extended output function",
    "certification level": "not certified",
    "Mode": "none"
  },
  "Serpent": {
    "cbc": {
      "128": {
        "Classic Security Level": "128",
        "Functions": [
          "keygen",
          "encrypt",
          "decrypt"
        ],
        "NIST_Security_Category": 2,
        "Primitive": "Block-cipher",
        "certification level": "not certified",
        "Mode": "CBC"
      },
      "192": {
        "Classic Security Level": "192",
        "Functions": [
          "keygen",
          "encrypt",
          "decrypt"
        ],
        "NIST_Security_Category": 3,
        "Primitive": "Block-cipher",
        "certification level": "not certified",
        "Mode": "CBC"
      },
      "256": {
        "Classic Security Level": "256",
        "Functions": [
          "keygen",
          "encrypt",
          "decrypt"
        ],
        "NIST_Security_Category": 4,
        "Primitive": "Block-cipher",
        "certification level": "not certified",
        "Mode": "CBC"
      }
    }
  },
  "scrypt": {
    "Classic Security Level": "128",
    "Functions": [
      "keygen", 
      "hashing"
    ],
    "NIST_Security_Category": 2,
    "Primitive": "Key Derivation Function",
    "certification level": "not certified",
    "Mode": "none"
  },
  "Sphincs+": {
    "Classic Security Level": "256",
    "Functions": [
      "keygen",
      "sign",
      "verify"
    ],
    "NIST_Security_Category": 5,
    "Primitive": "Signature",
    "certification level": "not certified",
    "Mode": "none"
  },
  "TLS": {
    "Classic Security Level": "128",
    "Functions": [
      "keygen",
      "key exchange",
      "authentication"
    ],
    "NIST_Security_Category": 2,
    "Primitive": "Protocol",
    "certification level": "fips140-2-l1",
    "Mode": "none"
  },
  "Threefish": {
    "Classic Security Level": "256",
    "Functions": [
      "keygen",
      "encrypt",
      "decrypt"
    ],
    "NIST_Security_Category": 3,
    "Primitive": "Block-cipher",
    "certification level": "not certified",
    "Mode": "none"
  },
  "Twofish": {
    "Classic Security Level": "128",
    "Functions": [
      "keygen",
      "encrypt",
      "decrypt"
    ],
    "NIST_Security_Category": 2,
    "Primitive": "Block-cipher",
    "certification level": "not certified",
    "Mode": "none"
  },
  "X25519": {
    "Classic Security Level": "128",
    "Functions": [
      "keygen",
      "key agreement"
    ],
    "NIST_Security_Category": 3,
    "Primitive": "Key agreement",
    "certification level": "not certified",
    "Mode": "none"
  },
  "X448": {
    "Classic Security Level": "224",
    "Functions": [
      "keygen",
      "key agreement"
    ],
    "NIST_Security_Category": 3,
    "Primitive": "Key agreement",
    "certification level": "not certified",
    "Mode": "none"
  }
}
