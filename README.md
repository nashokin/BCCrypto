# [BouncyCastle](http://bouncycastle.org) implementation of RSA-OAEP and OpenPGP encryption/decryption mechanisms

I've seen some people are having difficulties finding a complete working solution, which implements encryption and decryption with RSA-OAEP(Optimal Asymmetric Encryption Padding) and OpenPGP standards. This is my own implementation as a collection of thoughts from a task that I had implementated in my daily job. I hope some people will find it usefull and it will guide or help them in the idea being accomplished.

## Public/Private key generation instructions

I've tested this on Ubuntu (Native and in Windows Sybsystem for Linux), commands provided are for use in the Terminal. There are many other options to generate keys, this is my preferred option.

### RSA
- `openssl genrsa -aes256 -out private.pem 4096` -> this will be a guided prompt that will generate a private key
- `openssl rsa -in private.pem -pubout > public.pem` -> this will extract public key from a private key previously generated

### OpenPGP
- `gpg --full-generate-key` -> this will be a full guided prompt to generate a set of public and private keypair
- `gpg --list-keys` -> this will list all public keys, copy the key id for the next command
- `gpg --export -a 80C42804012256AF85D9AACAC3462FE2F1C35E09 > public.gpg` -> this will extract the public key to be used for encryption
- `gpg --list-secret-keys` -> this will list all private keys available, copy the id to be ued in the next command
- `gpg --export-secret-key -a 80C42804012256AF85D9AACAC3462FE2F1C35E09 > private.gpg` -> this will exctrat the private key for the id provided

#### TODO:
- Implement signature option with signing key for encrypted message with OpenPGP

Any comments/suggestions are very welcome, please enjoy.

![Robot Thumbs Up](https://raw.githubusercontent.com/nashokin/Base16-Tomorrow-Night/master/images/Robot-thumbs-up.png)
