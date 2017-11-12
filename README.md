# roca-crack
A utility for cracking RSA keys with low entropy prime factors.

## Generating Bad Keys
If you need a keypair to test the attack against you can generate one via:

```bash
$ python roca-crack/keygen.py
```

This will output an ascii-armored RSA public key and also run the [roca-detect](https://github.com/crocs-muni/roca)
utility against it to verify that the key is indeed vulnerable. It should go without saying, but just to be clear
**DO NOT USE THIS KEY TO DO ANYTHING IMPORTANT**. You can't do much damage with just the public key but if you do
recover the private exponent and for some insane reason starting using the private key to encrypt / sign data you
will be in trouble.
