
import math
import re
from collections import Counter
from urllib.parse import parse_qsl

METHOD_CODES = {
    "GET": 0,
    "POST": 1,
    "PUT": 2,
    "DELETE": 3,
    "PATCH": 4,
    "HEAD": 5,
    "OPTIONS": 6,
}


def entropy(text):
    if not text:
        return 0.0

    counts = Counter(text)
    n = len(text)

    return -sum(
        (count / n) * math.log2(count / n)
        for count in counts.values()
    )


def extract_features(request):
    path = request["path"]
    query = request["query"]
    body = request["body"]

    # Use content for numerical feature extraction only.
    # Never export credentials or raw payloads.
    payload = query + "&" + body
    decoded = payload.lower()

    special_count = sum(
        not c.isalnum() and not c.isspace()
        for c in payload
    )

    params = parse_qsl(query, keep_blank_values=True)

    return {
        "method_code": METHOD_CODES.get(
            request["method"], 7
        ),
        "path_length": len(path),
        "path_depth": sum(bool(p) for p in path.split("/")),
        "query_length": len(query),
        "query_param_count": len(params),
        "body_size": len(body.encode("latin-1")),
        "payload_entropy": entropy(payload),
        "special_char_ratio": (
            special_count / len(payload) if payload else 0.0
        ),
        "has_cookie": int(
            "cookie" in request["headers"]
        ),
        "content_length_header": int(
            request["headers"].get(
                "content-length", "0"
            ).isdigit()
            and request["headers"].get(
                "content-length", "0"
            ) or "0"
        ),
        "traversal_flag": int(
            "../" in decoded or "..%2f" in decoded
        ),
        "sql_marker_flag": int(bool(re.search(
            r"\bunion\s+select\b|"
            r"\bselect\b.{1,80}\bfrom\b|"
            r"\bor\s+1\s*=\s*1\b",
            decoded,
        ))),
    }
