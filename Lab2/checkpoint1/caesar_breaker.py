cipher = "odroboewscdrolocdcwkbdmyxdbkmdzvkdpybwyeddrobo"

english_freq = {
    'a':0.0805,'b':0.0167,'c':0.0223,'d':0.0510,'e':0.1222,'f':0.0214,'g':0.0230,'h':0.0662,
    'i':0.0628,'j':0.0019,'k':0.0095,'l':0.0408,'m':0.0233,'n':0.0695,'o':0.0763,'p':0.0166,
    'q':0.0006,'r':0.0529,'s':0.0602,'t':0.0967,'u':0.0292,'v':0.0082,'w':0.0260,'x':0.0011,
    'y':0.0204,'z':0.0006
}

import string

def shift_text(s, shift):
    res = []
    for ch in s:
        if ch.isalpha():
            i = ord(ch) - ord('a')
            res.append(chr((i - shift) % 26 + ord('a')))
        else:
            res.append(ch)
    return "".join(res)

def chi_squared_score(text):
    counts = {c: 0 for c in string.ascii_lowercase}
    total = 0
    for ch in text:
        if ch.isalpha():
            counts[ch] += 1
            total += 1
    if total == 0:
        return float('inf')

    score = 0.0
    for c in string.ascii_lowercase:
        observed = counts[c]
        expected = english_freq[c] * total
        score += ((observed - expected) ** 2) / (expected + 1e-9)
    return score

best = (1e18, None, None)
for sh in range(26):
    pt = shift_text(cipher, sh)
    sc = chi_squared_score(pt)
    if sc < best[0]:
        best = (sc, sh, pt)

print("Best shift:", best[1])
print("Decrypted plaintext:\n", best[2])

print("\n--- All shifts ---")
for sh in range(26):
    print(f"{sh:2d}: {shift_text(cipher, sh)}")
