def count_same_bits(h1, h2):
    b1 = bin(int(h1, 16))[2:].zfill(len(h1)*4)
    b2 = bin(int(h2, 16))[2:].zfill(len(h2)*4)
    return sum(c1 == c2 for c1, c2 in zip(b1, b2))

md5_h1 = "22ddefd429f01d440596e1c0fbb0ba11"
md5_h2 = "8eb741c8f8af9280c2c23aec1b13ecac"

sha256_h1 = "d33da148eec2467655d5aa7a0573690b2eff1c202ffe8a00dc40450dd7497735"
sha256_h2 = "f3b42231a30feada07b059dfe3bde836fc33661fd15b644264af182574a88709"

print("MD5 same bits:", count_same_bits(md5_h1, md5_h2))
print("SHA-256 same bits:", count_same_bits(sha256_h1, sha256_h2))
