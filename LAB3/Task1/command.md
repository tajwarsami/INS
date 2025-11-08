Commands used for AES Encryption
1. CBC Mode

Encryption

openssl enc -aes-128-cbc -e \
-in test.txt -out cipher-cbc.bin \
-K 00112233445566778899aabbccddeeff \
-iv 0102030405060708090a0b0c0d0e0f10


Decryption

openssl enc -aes-128-cbc -d \
-in cipher-cbc.bin -out decrypted-cbc.txt \
-K 00112233445566778899aabbccddeeff \
-iv 0102030405060708090a0b0c0d0e0f10

2️. CFB Mode

Encryption

openssl enc -aes-128-cfb -e \
-in test.txt -out cipher-cfb.bin \
-K 00112233445566778899aabbccddeeff \
-iv 0102030405060708090a0b0c0d0e0f10


Decryption

openssl enc -aes-128-cfb -d \
-in cipher-cfb.bin -out decrypted-cfb.txt \
-K 00112233445566778899aabbccddeeff \
-iv 0102030405060708090a0b0c0d0e0f10

3. OFB Mode

Encryption

openssl enc -aes-128-ofb -e \
-in test.txt -out cipher-ofb.bin \
-K 00112233445566778899aabbccddeeff \
-iv 0102030405060708090a0b0c0d0e0f10


Decryption

openssl enc -aes-128-ofb -d \
-in cipher-ofb.bin -out decrypted-ofb.txt \
-K 00112233445566778899aabbccddeeff \
-iv 0102030405060708090a0b0c0d0e0f10