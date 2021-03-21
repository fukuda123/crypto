#!/usr/bin/python3
# -*- coding: utf-8 -*-

import sys
import hashlib

def emsa_pkcs1_v1_5_encode(m, emlen):
    # Note: all arguments are integer

    # TODO: Output "message too long" if the bit-length of m is longer than 2^64 - 1

    m_bytes = m.to_bytes((m.bit_length() + 7) // 8, byteorder = 'big')

    h = hashlib.sha256(m_bytes).hexdigest()

    t = b"\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20" + bytes.fromhex(h)
    tlen = len(t)

    if emlen < tlen + 11:
        return "intended encoded message length too short"

    ps = b'\xff' * (emlen - tlen - 3)

    em = b'\x00\x01' + ps + b'\x00' + t

    return em

def rsassa_pkcs1_v1_5_sign(n, d, m):
    # Note: all arguments are hex-string

    k_int = 2048 // 8

    n_int = int(n, 16)
    d_int = int(d, 16)
    m_int = int(m, 16)

    em_bytes = emsa_pkcs1_v1_5_encode(m_int, k_int)
    if (em_bytes == "message too long"):
        return "message too long"
    if (em_bytes == "intended encoded message length too short"):
        return "RSA modulus too short"

    pt_int = int.from_bytes(em_bytes, 'big')

    s_int = pow(pt_int, d_int, n_int)

    s = format(s_int, 'x')

    return s

def rsassa_pkcs1_v1_5_verify(n, e, m, s):
    # Note: all arguments are hex-string

    k_int = 2048 // 8

    if (len(s) > k_int * 2):
        return "invalid signature"

    n_int = int(n, 16)
    e_int = int(e, 16)
    m_int = int(m, 16)
    s_int = int(s, 16)

    if (s_int < 0) or (s_int > n_int - 1):
        return "invalid signature"
    pt_int = pow(s_int, e_int, n_int)

    if (pt_int >= pow(256, k_int)):
        return "invalid signature"
    em1 = pt_int.to_bytes(k_int, 'big')

    em2 = emsa_pkcs1_v1_5_encode(m_int, k_int)
    if (em2 == "message too long"):
        return "message too long"
    if (em2 == "intended encoded message length too short"):
        return "RSA modulus too short"

    if (em1 == em2):
        return "valid signature"

    return "invalid signature"

if __name__ == "__main__":
    n = "9d9fa67beae61a1abef0bc06dbfe4d65068f97c7a1e7cc5b62bf400765769a5b3ba469656cadd0d1d42063cb736de9d9b5fc113f5ff0ac3b1017f9cb380de259f44462f446e74f62d4f4bca936334d7ca3a866b673bafa7a9d31dce267325a537e9686a4c8f80f0f5c11896d8e6aa8ff8e2b33fd1345feb76d73ddd7b3340b9e898d60944760e5e8c301d9c8fe4bd4bcab6519872a3572aab40f9b7d35b051493292b12e94def655a78e026d4862c52e7980256b6b368341dc0c325ac8f84bfc14d93d4f47ea606ae141c2f5a53eda53ecc2576d628d488f4966966d818be224014afa3b86c0aad6ee3a702386254ddb7d703a93be21ff7e26cd98b56182f6c3"
    e = "010001"
    d = "50b68ad2d38306850197564110efd483d1eb3fa68b229e43817a3b784e1d80870d307083ee35c7435b2346d6cc81d10899a6bcd23df788ca29c08d39e1b7425c1bb7d5100f2aad3d079d56ea3305ec3cd1b50efb88a18b57b41cef65c3c045fe9148d5239681677ccf016fe4f8d3673c8d795402d896b40b0b72147c3a988105da8bd50aa99d2fe6726ebdc15deae0d58f3691e010855dc18aff455c9ab1a3215dabdb5bbcf499afcd365aedf70f1ca75342cbef855908f3d8e5efcf893fdc5ebd91cb85a54fe82e5c90e2daafa16a9bc7731d41e56d4df3bcce582746d418839971a00039046c4cebc0c90bde647cc4cd427e580814acc309f11de8982c2419"
    m = "12345"
    s = rsassa_pkcs1_v1_5_sign(n, d, m)
    print("[Sign]")
    print(s)
    r = rsassa_pkcs1_v1_5_verify(n, e, m, s)
    print("[Verify]")
    print(r)
