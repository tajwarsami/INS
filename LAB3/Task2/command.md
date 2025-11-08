Task 2 — ECB vs CBC Mode (Weather.bmp)

 1️. ECB Mode
**Encryption**
```console
openssl enc -aes-128-ecb -e \-in weather.bmp -out weather_ecb_enc.bin \
-K 00112233445566778899aabbccddeeff
 2. CBC Mode
 openssl enc -aes-128-cbc -e \-in weather.bmp -out weather_cbc_enc.bin \
-K 00112233445566778899aabbccddeeff \
-iv 0102030405060708090a0b0c0d0e0f10
