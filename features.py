import math
import collections


def calculate_shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    text = text.lower()
    freq = collections.Counter(text)
    total = len(text)
    return round(-sum((c / total) * math.log2(c / total) for c in freq.values()), 4)


def extract_features(query_string: str) -> list:
    query = query_string.lower().strip().rstrip(".")
    labels = query.split(".")
    subdomains = labels[:-2] if len(labels) > 2 else labels[:1]
    subdomain_str = ".".join(subdomains) if subdomains else query

    query_length = len(query)
    subdomain_length = len(subdomain_str)
    entropy = calculate_shannon_entropy(query)
    vowels = set("aeiou")
    vowel_ratio = sum(1 for c in query if c in vowels) / max(len(query), 1)
    numeric_ratio = sum(1 for c in query if c.isdigit()) / max(len(query), 1)
    special_chars = sum(1 for c in query if not c.isalnum() and c != ".")
    special_ratio = special_chars / max(len(query), 1)
    max_label_len = max((len(l) for l in labels), default=0)
    label_count = len(labels)
    stripped = query.replace(".", "")
    unique_ratio = len(set(stripped)) / max(len(stripped), 1)

    return [
        query_length,
        subdomain_length,
        entropy,
        vowel_ratio,
        numeric_ratio,
        special_ratio,
        max_label_len,
        label_count,
        unique_ratio,
    ]


FEATURE_NAMES = [
    "query_length",
    "subdomain_length",
    "entropy",
    "vowel_ratio",
    "numeric_ratio",
    "special_ratio",
    "max_label_length",
    "label_count",
    "unique_char_ratio",
]
