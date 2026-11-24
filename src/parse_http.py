
import re
from pathlib import Path
from urllib.parse import urlsplit


REQUEST_LINE = re.compile(
    r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)"
    r"\s+(\S+)\s+(HTTP/\d(?:\.\d)?)$"
)


def parse_http_file(file_path):
    text = Path(file_path).read_text(
        encoding="latin-1",
        errors="replace",
    )

    records = []
    current = None
    header_section = True

    def save_current():
        if current is not None:
            records.append(current.copy())

    for line in text.splitlines():
        match = REQUEST_LINE.match(line.strip())

        if match:
            save_current()

            method, target, protocol = match.groups()
            parsed_url = urlsplit(target)

            current = {
                "method": method,
                "path": parsed_url.path or "/",
                "query": parsed_url.query,
                "protocol": protocol,
                "headers": {},
                "body": "",
            }
            header_section = True
            continue

        if current is None:
            continue

        if header_section:
            if not line.strip():
                header_section = False
                continue

            if ":" in line:
                key, value = line.split(":", 1)
                current["headers"][key.strip().lower()] = (
                    value.strip()
                )
        else:
            if current["body"]:
                current["body"] += "\n"
            current["body"] += line

    save_current()
    return records


if __name__ == "__main__":
    import sys

    input_path = Path(sys.argv[1])
    requests = parse_http_file(input_path)

    print("Parsed requests:", len(requests))

    for request in requests[:3]:
        # Deliberately do not print headers or body.
        print({
            "method": request["method"],
            "path": request["path"],
            "query_length": len(request["query"]),
            "body_length": len(request["body"]),
        })
