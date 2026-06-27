"""Classical ciphers and local attacks.

NOT SECURE. NEVER USE FOR REAL PROTECTION.
"""

from __future__ import annotations

import math
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from itertools import pairwise

from feltcrypto.foundations import english_score, index_of_coincidence

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
ENGLISH_LETTER_FREQUENCY = {
    "A": 0.08167,
    "B": 0.01492,
    "C": 0.02782,
    "D": 0.04253,
    "E": 0.12702,
    "F": 0.02228,
    "G": 0.02015,
    "H": 0.06094,
    "I": 0.06966,
    "J": 0.00153,
    "K": 0.00772,
    "L": 0.04025,
    "M": 0.02406,
    "N": 0.06749,
    "O": 0.07507,
    "P": 0.01929,
    "Q": 0.00095,
    "R": 0.05987,
    "S": 0.06327,
    "T": 0.09056,
    "U": 0.02758,
    "V": 0.00978,
    "W": 0.02360,
    "X": 0.00150,
    "Y": 0.01974,
    "Z": 0.00074,
}


def _english_score_text(text: str) -> float:
    """Score text as English, tolerating non-ASCII bytes instead of crashing."""

    return english_score(text.encode("ascii", errors="replace"))


@dataclass(frozen=True)
class TextCandidate:
    key: str
    plaintext: str
    score: float


def _shift_char(char: str, shift: int) -> str:
    if not char.isascii() or not char.isalpha():
        return char
    base = ord("A") if char.isupper() else ord("a")
    return chr((ord(char) - base + shift) % 26 + base)


def caesar_encrypt(plaintext: str, key: int) -> str:
    """Shift every letter by ``key`` positions, leaving non-letters untouched."""

    return "".join(_shift_char(char, key) for char in plaintext)


def caesar_decrypt(ciphertext: str, key: int) -> str:
    return caesar_encrypt(ciphertext, -key)


def break_caesar(ciphertext: str, top_n: int = 5) -> list[TextCandidate]:
    """Try all 26 shifts and rank them by English-likeness.

    The whole key space is tiny, so brute force plus a frequency score recovers
    the plaintext immediately.
    """

    candidates = [
        TextCandidate(str(key), caesar_decrypt(ciphertext, key), 0.0) for key in range(26)
    ]
    scored = [
        TextCandidate(item.key, item.plaintext, _english_score_text(item.plaintext))
        for item in candidates
    ]
    return sorted(scored, key=lambda item: item.score, reverse=True)[:top_n]


def substitution_encrypt(plaintext: str, alphabet: str) -> str:
    normalized = alphabet.upper()
    if len(normalized) != 26 or set(normalized) != set(ALPHABET):
        raise ValueError("substitution alphabet must contain A-Z exactly once")
    mapping = dict(zip(ALPHABET, normalized, strict=True))
    output = []
    for char in plaintext:
        upper = char.upper()
        if upper not in mapping:
            output.append(char)
            continue
        replacement = mapping[upper]
        output.append(replacement if char.isupper() else replacement.lower())
    return "".join(output)


def substitution_decrypt(ciphertext: str, alphabet: str) -> str:
    normalized = alphabet.upper()
    reverse_alphabet = [""] * 26
    for plain, cipher in zip(ALPHABET, normalized, strict=True):
        reverse_alphabet[ord(cipher) - ord("A")] = plain
    return substitution_encrypt(ciphertext, "".join(reverse_alphabet))


def word_pattern(word: str) -> tuple[int, ...]:
    seen: dict[str, int] = {}
    return tuple(seen.setdefault(char, len(seen)) for char in word.lower())


def break_substitution(ciphertext: str, vocabulary: tuple[str, ...]) -> TextCandidate:
    """Solve a bundled phrase using repeated-letter and common-word patterns.

    This is intentionally a small, transparent constraint solver rather than a
    general ciphertext-breaking interface.
    """

    cipher_words = re.findall(r"[A-Za-z]+", ciphertext.lower())
    pattern_index: dict[tuple[int, tuple[int, ...]], list[str]] = defaultdict(list)
    for word in vocabulary:
        pattern_index[(len(word), word_pattern(word))].append(word.lower())

    distinct_words = list(dict.fromkeys(cipher_words))
    candidate_words = {
        word: pattern_index[(len(word), word_pattern(word))] for word in distinct_words
    }
    if any(not candidates for candidates in candidate_words.values()):
        raise ValueError("bundled vocabulary does not cover every ciphertext word pattern")

    solutions: list[dict[str, str]] = []

    def compatible(
        cipher_word: str,
        plain_word: str,
        cipher_to_plain: dict[str, str],
        plain_to_cipher: dict[str, str],
    ) -> bool:
        return all(
            cipher_to_plain.get(cipher, plain) == plain
            and plain_to_cipher.get(plain, cipher) == cipher
            for cipher, plain in zip(cipher_word, plain_word, strict=True)
        )

    def search(
        remaining: tuple[str, ...],
        cipher_to_plain: dict[str, str],
        plain_to_cipher: dict[str, str],
    ) -> None:
        if len(solutions) >= 500:
            return
        if not remaining:
            solutions.append(cipher_to_plain)
            return

        ranked: list[tuple[int, str, list[str]]] = []
        for cipher_word in remaining:
            valid = [
                plain_word
                for plain_word in candidate_words[cipher_word]
                if compatible(cipher_word, plain_word, cipher_to_plain, plain_to_cipher)
            ]
            ranked.append((len(valid), cipher_word, valid))
        _, chosen, valid_words = min(ranked, key=lambda item: item[0])
        next_remaining = tuple(word for word in remaining if word != chosen)

        for plain_word in valid_words:
            next_c2p = dict(cipher_to_plain)
            next_p2c = dict(plain_to_cipher)
            for cipher, plain in zip(chosen, plain_word, strict=True):
                next_c2p[cipher] = plain
                next_p2c[plain] = cipher
            search(next_remaining, next_c2p, next_p2c)

    search(tuple(distinct_words), {}, {})
    if not solutions:
        raise ValueError("no substitution candidate matched the local vocabulary")

    ranked_solutions: list[TextCandidate] = []
    for mapping in solutions:
        plaintext = "".join(mapping.get(char.lower(), char) for char in ciphertext)
        common_word_bonus = sum(
            0.04 for word in re.findall(r"[a-z]+", plaintext) if word in vocabulary
        )
        ranked_solutions.append(
            TextCandidate(
                key="".join(mapping.get(char.lower(), "?") for char in ALPHABET.lower()),
                plaintext=plaintext,
                score=_english_score_text(plaintext) + common_word_bonus,
            )
        )
    return max(ranked_solutions, key=lambda item: item.score)


def vigenere_encrypt(plaintext: str, key: str) -> str:
    """Apply a repeating sequence of Caesar shifts taken from the key letters."""

    shifts = [ord(char) - ord("A") for char in key.upper() if char.isalpha()]
    if not shifts:
        raise ValueError("Vigenere key must contain letters")
    output: list[str] = []
    key_index = 0
    for char in plaintext:
        if char.isascii() and char.isalpha():
            output.append(_shift_char(char, shifts[key_index % len(shifts)]))
            key_index += 1
        else:
            output.append(char)
    return "".join(output)


def vigenere_decrypt(ciphertext: str, key: str) -> str:
    # Filter non-letters exactly as vigenere_encrypt does, so the inverse key is
    # the same length and the encrypt/decrypt pair stays symmetric.
    inverse = "".join(
        chr((26 - (ord(char) - 65)) % 26 + 65) for char in key.upper() if char.isalpha()
    )
    return vigenere_encrypt(ciphertext, inverse)


def _chi_squared_for_shift(column: str, shift: int) -> float:
    if not column:
        return math.inf
    decrypted = [chr((ord(char) - 65 - shift) % 26 + 65) for char in column]
    counts = Counter(decrypted)
    length = len(decrypted)
    return sum(
        ((counts[letter] - length * expected) ** 2) / (length * expected)
        for letter, expected in ENGLISH_LETTER_FREQUENCY.items()
    )


def _kasiski_votes(letters: str, maximum_key_length: int) -> Counter[int]:
    locations: dict[str, list[int]] = defaultdict(list)
    for index in range(len(letters) - 2):
        locations[letters[index : index + 3]].append(index)
    votes: Counter[int] = Counter()
    for positions in locations.values():
        if len(positions) < 2:
            continue
        for first, second in pairwise(positions):
            distance = second - first
            for factor in range(2, maximum_key_length + 1):
                if distance % factor == 0:
                    votes[factor] += 1
    return votes


def break_vigenere(ciphertext: str, maximum_key_length: int = 12) -> list[TextCandidate]:
    """Recover key and plaintext by guessing the period, then solving columns.

    Kasiski votes and the index of coincidence suggest the key length; each
    resulting column is an independent Caesar cipher solved by chi-squared fit.
    """

    letters = "".join(char for char in ciphertext.upper() if char.isalpha())
    if not letters:
        return []
    # Never test a key longer than the available letters, or some columns would
    # be empty and chi-squared scoring would divide by zero.
    effective_max = min(maximum_key_length, len(letters))
    kasiski = _kasiski_votes(letters, effective_max)
    candidates: list[TextCandidate] = []
    for key_length in range(1, effective_max + 1):
        columns = [letters[index::key_length] for index in range(key_length)]
        key = "".join(
            chr(min(range(26), key=lambda shift: _chi_squared_for_shift(column, shift)) + ord("A"))
            for column in columns
        )
        plaintext = vigenere_decrypt(ciphertext, key)
        average_ioc = sum(index_of_coincidence(column) for column in columns) / key_length
        structure_bonus = -abs(0.066 - average_ioc) + 0.0002 * kasiski[key_length]
        score = _english_score_text(plaintext) + structure_bonus - key_length * 0.0005
        candidates.append(TextCandidate(key, plaintext, score))
    return sorted(candidates, key=lambda item: item.score, reverse=True)


def caesar_frequency_guess(ciphertext: str) -> int:
    letters = Counter(char.upper() for char in ciphertext if char.isalpha())
    if not letters:
        raise ValueError("ciphertext contains no letters")
    most_common = letters.most_common(1)[0][0]
    return (ord(most_common) - ord("E")) % 26


def confidence_gap(candidates: list[TextCandidate]) -> float:
    if len(candidates) < 2:
        return math.inf
    return candidates[0].score - candidates[1].score
