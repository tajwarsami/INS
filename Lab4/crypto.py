import argparse
import os
import sys
import time
import hashlib
import struct
from pathlib import Path
from typing import Tuple

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

try:
    import matplotlib.pyplot as plt
except Exception:
    plt = None

AES_KEY_128_FILE = "aes_key_128.bin"
AES_KEY_256_FILE = "aes_key_256.bin"
RSA_PRIV_FILE = "rsa_private.pem"
RSA_PUB_FILE = "rsa_public.pem"


def save_bytes(path: str, data: bytes):
    with open(path, "wb") as f:
        f.write(data)


def load_bytes(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


# AES

def derive_aes_key_from_entropy(entropy_bits: int, key_size_bits: int) -> bytes:
    """
    Derive an AES key of key_size_bits from entropy_bits of random data.
    This is used so the benchmark can vary the N (entropy) while using a standard AES key length.
    """
    if key_size_bits not in (128, 192, 256):
        raise ValueError("AES key size must be 128, 192 or 256 bits")
    byte_len = (entropy_bits + 7) // 8
    if byte_len <= 0:
        byte_len = 1
    entropy = get_random_bytes(byte_len)
    digest = hashlib.sha256(entropy).digest()
    key_bytes = digest[: key_size_bits // 8]
    return key_bytes


def aes_encrypt_file(infile: str, outfile: str, key: bytes, mode: str):
    data = load_bytes(infile)
    mode = mode.upper()
    if mode == "ECB":
        cipher = AES.new(key, AES.MODE_ECB)
        ciphertext = cipher.encrypt(pad(data, AES.block_size))
        save_bytes(outfile, ciphertext)
    elif mode == "CFB":
        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(key, AES.MODE_CFB, iv=iv)
        ciphertext = iv + cipher.encrypt(data)
        save_bytes(outfile, ciphertext)
    else:
        raise ValueError("Unsupported AES mode: use ECB or CFB")


def aes_decrypt_file(infile: str, outfile: str, key: bytes, mode: str):
    data = load_bytes(infile)
    mode = mode.upper()
    if mode == "ECB":
        cipher = AES.new(key, AES.MODE_ECB)
        plaintext = unpad(cipher.decrypt(data), AES.block_size)
        save_bytes(outfile, plaintext)
    elif mode == "CFB":
        iv = data[: AES.block_size]
        ciphertext = data[AES.block_size :]
        cipher = AES.new(key, AES.MODE_CFB, iv=iv)
        plaintext = cipher.decrypt(ciphertext)
        save_bytes(outfile, plaintext)
    else:
        raise ValueError("Unsupported AES mode: use ECB or CFB")


# RSA

def generate_rsa_keys(bits: int) -> Tuple[bytes, bytes]:
    key = RSA.generate(bits)
    priv = key.export_key()
    pub = key.publickey().export_key()
    return priv, pub


def rsa_encrypt_file(infile: str, outfile: str, pubkey_pem: bytes):
    pubkey = RSA.import_key(pubkey_pem)
    cipher = PKCS1_OAEP.new(pubkey)
    data = load_bytes(infile)
    key_size_bytes = pubkey.size_in_bytes()

    max_chunk = key_size_bytes - 2 - 2 * 20
    if max_chunk <= 0:
        raise ValueError("Public key too small to use OAEP chunking")
    chunks = [data[i : i + max_chunk] for i in range(0, len(data), max_chunk)]
    encrypted = b"".join(cipher.encrypt(chunk) for chunk in chunks)
    save_bytes(outfile, encrypted)


def rsa_decrypt_file(infile: str, outfile: str, privkey_pem: bytes):
    priv = RSA.import_key(privkey_pem)
    cipher = PKCS1_OAEP.new(priv)
    data = load_bytes(infile)
    key_size_bytes = priv.size_in_bytes()
    if len(data) % key_size_bytes != 0:
        pass
    chunks = [data[i : i + key_size_bytes] for i in range(0, len(data), key_size_bytes)]
    decrypted = b"".join(cipher.decrypt(chunk) for chunk in chunks)
    save_bytes(outfile, decrypted)


def rsa_sign_file(infile: str, outfile: str, privkey_pem: bytes):
    priv = RSA.import_key(privkey_pem)
    data = load_bytes(infile)
    h = hashlib.sha256(data).digest()
    signature = pkcs1_15.new(priv).sign(RSA._RSAobj._import_key(priv).hash_obj or RSA.import_key(priv)) if False else None
    signer = pkcs1_15.new(priv)
    from Crypto.Hash import SHA256

    hobj = SHA256.new(data=data)
    sig = signer.sign(hobj)
    save_bytes(outfile, sig)


def rsa_verify_file(infile: str, sigfile: str, pubkey_pem: bytes) -> bool:
    pub = RSA.import_key(pubkey_pem)
    data = load_bytes(infile)
    sig = load_bytes(sigfile)
    from Crypto.Hash import SHA256

    hobj = SHA256.new(data=data)
    try:
        pkcs1_15.new(pub).verify(hobj, sig)
        return True
    except (ValueError, TypeError):
        return False


# Hash 

def sha256_file(infile: str) -> str:
    h = hashlib.sha256()
    with open(infile, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def cmd_genkeys(args):
    # AES keys
    key128 = get_random_bytes(16)
    key256 = get_random_bytes(32)
    save_bytes(AES_KEY_128_FILE, key128)
    save_bytes(AES_KEY_256_FILE, key256)
    print(f"Saved AES-128 key to {AES_KEY_128_FILE} ({len(key128)*8} bits)")
    print(f"Saved AES-256 key to {AES_KEY_256_FILE} ({len(key256)*8} bits)")

    # RSA key pair
    priv, pub = generate_rsa_keys(2048)
    save_bytes(RSA_PRIV_FILE, priv)
    save_bytes(RSA_PUB_FILE, pub)
    print(f"Saved RSA private key to {RSA_PRIV_FILE} and public key to {RSA_PUB_FILE}")


def cmd_aes(args):
    size = args.size
    mode = args.mode
    if size == 128:
        key_path = AES_KEY_128_FILE
    elif size == 256:
        key_path = AES_KEY_256_FILE
    else:
        print("AES size must be 128 or 256")
        return
    if not os.path.exists(key_path):
        print(f"Key file {key_path} not found. Run 'genkeys' first or provide key file manually.")
        return
    key = load_bytes(key_path)
    start = time.perf_counter()
    if args.action == "encrypt":
        aes_encrypt_file(args.infile, args.outfile, key, mode)
        op = "encrypt"
    else:
        aes_decrypt_file(args.infile, args.outfile, key, mode)
        op = "decrypt"
    elapsed = time.perf_counter() - start
    print(f"AES {op} ({size}, {mode}) done in {elapsed:.6f} seconds. Output: {args.outfile}")


def cmd_rsa(args):
    if not os.path.exists(RSA_PRIV_FILE) or not os.path.exists(RSA_PUB_FILE):
        print("RSA keys not found. Run 'genkeys' first.")
        return
    priv = load_bytes(RSA_PRIV_FILE)
    pub = load_bytes(RSA_PUB_FILE)
    start = time.perf_counter()
    if args.action == "encrypt":
        rsa_encrypt_file(args.infile, args.outfile, pub)
        op = "encrypt"
    else:
        rsa_decrypt_file(args.infile, args.outfile, priv)
        op = "decrypt"
    elapsed = time.perf_counter() - start
    print(f"RSA {op} done in {elapsed:.6f} seconds. Output: {args.outfile}")


def cmd_sign(args):
    if not os.path.exists(RSA_PRIV_FILE) or not os.path.exists(RSA_PUB_FILE):
        print("RSA keys not found. Run 'genkeys' first.")
        return
    priv = load_bytes(RSA_PRIV_FILE)
    start = time.perf_counter()
    rsa_sign_file(args.infile, args.outfile, priv)
    elapsed = time.perf_counter() - start
    print(f"Signature generated in {elapsed:.6f} seconds. Signature file: {args.outfile}")


def cmd_verify(args):
    if not os.path.exists(RSA_PUB_FILE):
        print("RSA public key not found. Run 'genkeys' first.")
        return
    pub = load_bytes(RSA_PUB_FILE)
    start = time.perf_counter()
    ok = rsa_verify_file(args.infile, args.sigfile, pub)
    elapsed = time.perf_counter() - start
    print(f"Verification returned {ok} in {elapsed:.6f} seconds.")


def cmd_hash(args):
    h = sha256_file(args.infile)
    print(f"SHA-256({args.infile}) = {h}")


def cmd_bench(args):
    aes_ns = args.aes_ns or [16, 64, 128, 256]
    rsa_ns = args.rsa_ns or [16, 64, 128, 256, 512]
    repeat = args.repeat or 3
    results = {"aes": {}, "rsa": {}}

    payload = get_random_bytes(128 * 1024)  
    tmp_in = "__bench_tmp_in.bin"
    tmp_out = "__bench_tmp_out.bin"
    save_bytes(tmp_in, payload)

    print("Starting AES benchmark (deriving AES key from N bits of entropy)")
    for n in aes_ns:
        times = []
        for r in range(repeat):
            key = derive_aes_key_from_entropy(n, 128 if args.aes_size == 128 else 256)
            t0 = time.perf_counter()
            if args.aes_mode == "ECB":
                aes_encrypt_file(tmp_in, tmp_out, key, "ECB")
                aes_decrypt_file(tmp_out, tmp_out + ".dec", key, "ECB")
            else:
                aes_encrypt_file(tmp_in, tmp_out, key, "CFB")
                aes_decrypt_file(tmp_out, tmp_out + ".dec", key, "CFB")
            t1 = time.perf_counter()
            times.append(t1 - t0)
        avg = sum(times) / len(times)
        results["aes"][n] = avg
        print(f"AES N={n} bits: avg time {avg:.6f}s over {repeat} runs")

    print("Starting RSA benchmark (key generation + encrypt/decrypt of small message)")
    small_msg = b"Test message for RSA" * 4
    tmp_in2 = "__bench_tmp_in2.bin"
    tmp_out2 = "__bench_tmp_out2.bin"
    save_bytes(tmp_in2, small_msg)
    for n in rsa_ns:
        times = []
        for r in range(repeat):
            t0 = time.perf_counter()
            priv, pub = generate_rsa_keys(n)
            rsa_encrypt_file(tmp_in2, tmp_out2, pub)
            rsa_decrypt_file(tmp_out2, tmp_out2 + ".dec", priv)
            t1 = time.perf_counter()
            times.append(t1 - t0)
        avg = sum(times) / len(times)
        results["rsa"][n] = avg
        print(f"RSA N={n} bits: avg time {avg:.6f}s over {repeat} runs")
    if plt is not None:
        # AES plot
        aes_x = sorted(results["aes"].keys())
        aes_y = [results["aes"][x] for x in aes_x]
        plt.figure()
        plt.plot(aes_x, aes_y, marker='o')
        plt.title(f"AES ({args.aes_size} bit) timing vs N (entropy bits) - mode {args.aes_mode}")
        plt.xlabel("N (bits)")
        plt.ylabel("Time (s)")
        plt.grid(True)
        aes_png = "aes_bench.png"
        plt.savefig(aes_png)

        rsa_x = sorted(results["rsa"].keys())
        rsa_y = [results["rsa"][x] for x in rsa_x]
        plt.figure()
        plt.plot(rsa_x, rsa_y, marker='o')
        plt.title("RSA timing vs N (modulus bits)")
        plt.xlabel("N (bits)")
        plt.ylabel("Time (s)")
        plt.grid(True)
        rsa_png = "rsa_bench.png"
        plt.savefig(rsa_png)
        print(f"Saved plots: {aes_png}, {rsa_png}")
    else:
        print("matplotlib not available: skipping plots. Install matplotlib to enable plots.")

    for f in [tmp_in, tmp_out, tmp_out + ".dec", tmp_in2, tmp_out2, tmp_out2 + ".dec"]:
        try:
            os.remove(f)
        except Exception:
            pass


def build_parser():
    p = argparse.ArgumentParser(description="Lab 4: Symmetric & Asymmetric Crypto Tool")
    sub = p.add_subparsers(dest="cmd")

    p_gen = sub.add_parser("genkeys", help="Generate AES and RSA keys (saved to files)")
    p_gen.set_defaults(func=cmd_genkeys)

    p_aes = sub.add_parser("aes", help="AES encrypt/decrypt using stored keys")
    p_aes.add_argument("action", choices=["encrypt", "decrypt"])
    p_aes.add_argument("--mode", choices=["ECB", "CFB"], default="ECB")
    p_aes.add_argument("--size", type=int, choices=[128, 256], default=128)
    p_aes.add_argument("-i", "--infile", required=True)
    p_aes.add_argument("-o", "--outfile", required=True)
    p_aes.set_defaults(func=cmd_aes)

    p_rsa = sub.add_parser("rsa", help="RSA encrypt/decrypt using stored keys")
    p_rsa.add_argument("action", choices=["encrypt", "decrypt"])
    p_rsa.add_argument("-i", "--infile", required=True)
    p_rsa.add_argument("-o", "--outfile", required=True)
    p_rsa.set_defaults(func=cmd_rsa)

    p_sign = sub.add_parser("sign", help="Generate RSA signature for file")
    p_sign.add_argument("-i", "--infile", required=True)
    p_sign.add_argument("-o", "--outfile", required=True)
    p_sign.set_defaults(func=cmd_sign)

    p_verify = sub.add_parser("verify", help="Verify RSA signature for file")
    p_verify.add_argument("-i", "--infile", required=True)
    p_verify.add_argument("-s", "--sigfile", required=True)
    p_verify.set_defaults(func=cmd_verify)

    p_hash = sub.add_parser("hash", help="Compute SHA-256 of a file")
    p_hash.add_argument("-i", "--infile", required=True)
    p_hash.set_defaults(func=cmd_hash)

    p_bench = sub.add_parser("bench", help="Benchmark AES and RSA across N values and plot results")
    p_bench.add_argument("--aes_ns", nargs="*", type=int, help="List of N values (bits) for AES entropy")
    p_bench.add_argument("--rsa_ns", nargs="*", type=int, help="List of N values (bits) for RSA modulus")
    p_bench.add_argument("--aes_size", type=int, choices=[128, 256], default=128, help="AES key size to test (128/256)")
    p_bench.add_argument("--aes_mode", choices=["ECB", "CFB"], default="CFB", help="AES mode for benchmark")
    p_bench.add_argument("--repeat", type=int, default=3)
    p_bench.set_defaults(func=cmd_bench)

    return p


def main():
    p = build_parser()
    args = p.parse_args()
    if not hasattr(args, "func"):
        p.print_help()
        return
    args.func(args)


if __name__ == "__main__":
    main()
