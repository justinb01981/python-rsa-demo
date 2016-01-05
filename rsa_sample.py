#!/usr/bin/env python

### pip install rsa ###
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
### should be SHA
from Crypto.Hash import MD5 as hash_alg

import sys, base64

### (pubkey, privkey) = rsa.newkeys(4096, 1) ###

try:
    key_pub = RSA.importKey(open('key_public.pem', 'r').read())
    key_priv = RSA.importKey(open('key_private.pem', 'r').read())
except:
    key_priv = None

def rsa_encrypt_and_b64encode(key, buf):
    result = key.encrypt(buf, None)
    return base64.b64encode(result[0])

def rsa_b64decode_and_decrypt(key, buf):
    b = base64.b64decode(buf)
    return key.decrypt(b)

result = 0

if len(sys.argv) < 2 or sys.argv[1] == '-?':
    print 'usage: ' + sys.argv[0] + ' [-p | -e | -d | -s | -v ] [signature]\n'
    print '\t-p: print public key'
    print '\t-e: encrypt $STDIN using public key'
    print '\t-d: decrypt $STDIN using private key'
    print '\t-s: MD5/PKCSv15 sign $STDIN'
    print '\t-v: verify [signature] for $STDIN'
    buf = ''
    test_buf = ''
else:
    buf = sys.stdin.read()
    test_buf = buf.encode('utf8')

if sys.argv[1] == '-e':
### encrypt using public key ###
    cryptbuf = rsa_encrypt_and_b64encode(key_pub, test_buf)
    print cryptbuf
elif sys.argv[1] == '-p':
    print base64.b64encode(key_pub)
elif sys.argv[1] == '-s':
    h = hash_alg.new(test_buf)
    signer = PKCS1_v1_5.new(key_priv)
    signature = signer.sign(h)
    print base64.b64encode(signature)
elif sys.argv[1] == '-v':
    sig = base64.b64decode(sys.argv[2])
    h = hash_alg.new(test_buf)
    signer = PKCS1_v1_5.new(key_pub)
    if signer.verify(h, sig):
        print 'signature: OK!'
    else:
        print 'signature: FAIL'
        result = -1
elif sys.argv[1] == '-d':
    cryptbuf = buf
### decrypt using private key ###
    cleartext = rsa_b64decode_and_decrypt(key_priv, cryptbuf)
    print cleartext

sys.exit(result)
