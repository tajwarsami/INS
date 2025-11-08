# checkpoint2_cipher1_solver.py
# Solves Checkpoint 2 Cipher 1 (Monoalphabetic Substitution)
# Usage: python3 checkpoint2_cipher1_solver.py cipher1.txt

import re, math, random, sys

english_freq = {
    'E':12.0, 'T':9.10, 'A':8.12, 'O':7.68, 'I':7.31, 'N':6.95, 'S':6.28,
    'R':6.02, 'H':5.92, 'D':4.32, 'L':3.98, 'U':2.88, 'C':2.71, 'M':2.61,
    'F':2.30, 'Y':2.11, 'W':2.09, 'G':2.03, 'P':1.82, 'B':1.49, 'V':1.11,
    'K':0.69, 'X':0.17, 'Q':0.11, 'J':0.10, 'Z':0.07
}

def read_file(path):
    with open(path, "r") as f:
        return f.read().upper()

def apply_key(text, key):
    table = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", key)
    return text.translate(table)

def random_key():
    letters = list("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    random.shuffle(letters)
    return "".join(letters)

def mutate_key(key):
    a, b = random.sample(range(26), 2)
    k = list(key)
    k[a], k[b] = k[b], k[a]
    return "".join(k)

def frequency_score(text):
    counts = {ch: text.count(ch) for ch in english_freq}
    total = sum(counts.values()) or 1
    score = 0
    for ch, freq in english_freq.items():
        observed = counts[ch] / total * 100
        score += abs(freq - observed)
    return -score

def solve_substitution(cipher):
    cipher = re.sub(r'[^A-Z]', '', cipher)
    best_key = random_key()
    best_score = frequency_score(apply_key(cipher, best_key))
    temperature = 5.0

    for _ in range(6000):
        candidate = mutate_key(best_key)
        cand_score = frequency_score(apply_key(cipher, candidate))
        delta = cand_score - best_score
        if delta > 0 or math.exp(delta / temperature) > random.random():
            best_key, best_score = candidate, cand_score
        temperature *= 0.999
    return best_key, apply_key(cipher, best_key)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 checkpoint2_cipher1_solver.py cipher1.txt")
        sys.exit()

    cipher_text = read_file(sys.argv[1])
    key, plaintext = solve_substitution(cipher_text)
    print("\n---- Decrypted Cipher 1 ----\n")
    print(plaintext)
    print("\n---- Key Mapping ----")
    for c, p in zip("ABCDEFGHIJKLMNOPQRSTUVWXYZ", key):
        print(f"{c} -> {p}")
