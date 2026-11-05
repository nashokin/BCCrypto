# RSA-OAEP and OpenPGP encryption/decryption

[BouncyCastle](http://bouncycastle.org) implementation of encryption and decryption mechanisms with **RSA-OAEP**(Optimal Asymmetric Encryption Padding) and **OpenPGP** standards.

## Public/Private key generation instructions

The below commands are to be run on Linux systems.

### RSA
- `openssl genrsa -aes256 -out private.pem 4096` -> this will be a guided prompt that will generate a private key
- `openssl rsa -in private.pem -pubout > public.pem` -> this will extract public key from a private key previously generated

### OpenPGP
- `gpg --full-generate-key` -> this will be a full guided prompt to generate a set of public and private keypair
- `gpg --list-keys` -> this will list all public keys, copy the key id for the next command
- `gpg --export -a 80C42804012256AF85D9AACAC3462FE2F1C35E09 > public.gpg` -> this will extract the public key to be used for encryption
- `gpg --list-secret-keys` -> this will list all private keys available, copy the id to be ued in the next command
- `gpg --export-secret-key -a 80C42804012256AF85D9AACAC3462FE2F1C35E09 > private.gpg` -> this will exctrat the private key for the id provided
