
import ipaddress
from functools import lru_cache
from urllib.parse import urlsplit, urlunsplit

from data_loader import load_dataset


@lru_cache(maxsize=1)
def get_url_index():
    dataset = load_dataset()
    dataset = dataset.drop_duplicates(
        subset=["normalized_url"]
    )
    return dataset.set_index("normalized_url", drop=False)


def normalize_url(url):
    if not isinstance(url, str) or not url.strip():
        raise ValueError("URL을 입력해 주세요.")

    url = url.strip()

    if any(char.isspace() for char in url):
        raise ValueError("URL에 공백이 포함되어 있습니다.")

    if "://" not in url:
        url = "http://" + url

    try:
        parts = urlsplit(url)
        hostname = parts.hostname
        port = parts.port
    except ValueError:
        raise ValueError("올바른 URL 형식이 아닙니다.")

    if not parts.scheme or not hostname:
        raise ValueError("올바른 URL 형식이 아닙니다.")

    scheme = parts.scheme.lower()
    hostname = hostname.lower()

    if parts.username or parts.password:
        user_info = parts.netloc.rsplit("@", 1)[0] + "@"
    else:
        user_info = ""

    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"

    netloc = user_info + hostname

    if port is not None:
        netloc += f":{port}"

    path = parts.path or "/"

    return urlunsplit((
        scheme,
        netloc,
        path,
        parts.query,
        ""
    ))


def extract_features(normalized_url):
    parts = urlsplit(normalized_url)
    hostname = parts.hostname or ""
    path = parts.path or ""

    try:
        ipaddress.ip_address(hostname)
        has_ip = True
    except ValueError:
        has_ip = False

    return {
        "url_length": len(normalized_url),
        "hostname_length": len(hostname),
        "subdomain_count": max(0, len(hostname.split(".")) - 2),
        "digit_count": sum(char.isdigit() for char in normalized_url),
        "special_char_count": sum(
            not char.isalnum() for char in normalized_url
        ),
        "has_ip": has_ip,
        "uses_https": parts.scheme.lower() == "https",
        "has_at": "@" in parts.netloc,
        "has_hyphen": "-" in hostname,
        "has_double_slash": "//" in path,
        "has_port": parts.port is not None,
        "path_length": len(path),
        "query_length": len(parts.query)
    }


def calculate_risk(features):
    score = 0
    reasons = []

    if features["has_ip"]:
        score += 30
        reasons.append("도메인 대신 IP 주소를 사용합니다.")

    if features["has_at"]:
        score += 25
        reasons.append("주소에 @ 문자가 포함되어 있습니다.")

    if features["url_length"] >= 100:
        score += 15
        reasons.append("URL 길이가 매우 깁니다.")

    if features["hostname_length"] >= 40:
        score += 10
        reasons.append("호스트 이름이 지나치게 깁니다.")

    if features["subdomain_count"] >= 4:
        score += 10
        reasons.append("하위 도메인이 여러 단계로 구성되어 있습니다.")

    if features["has_port"]:
        score += 10
        reasons.append("포트 번호가 포함되어 있습니다.")

    if features["digit_count"] >= 15:
        score += 10
        reasons.append("URL에 숫자가 많이 포함되어 있습니다.")

    if features["special_char_count"] >= 30:
        score += 10
        reasons.append("특수문자가 많이 포함되어 있습니다.")

    if not features["uses_https"]:
        score += 5
        reasons.append("HTTPS를 사용하지 않습니다.")

    return min(score, 100), reasons


def analyze_url(url, dataset=None):
    try:
        normalized_url = normalize_url(url)
    except ValueError as error:
        return {
            "url": url,
            "normalized_url": "",
            "status": "미확인",
            "risk_score": 0,
            "reasons": [str(error)],
            "source": "입력값 검증"
        }

    if dataset is None:
        url_index = get_url_index()
        matched = url_index.loc[
            [normalized_url]
        ] if normalized_url in url_index.index else None
    else:
        matched = dataset[
            dataset["normalized_url"] == normalized_url
        ]

    if matched is not None and not matched.empty:
        record = matched.iloc[0]
        label = int(record["label"])
        source = str(record["source"])

        if label == 1:
            return {
                "url": url,
                "normalized_url": normalized_url,
                "status": "악성",
                "risk_score": 100,
                "reasons": [
                    "악성 URL 데이터베이스에서 일치하는 주소가 확인되었습니다."
                ],
                "source": source
            }

        if label == 0:
            return {
                "url": url,
                "normalized_url": normalized_url,
                "status": "정상 후보",
                "risk_score": 0,
                "reasons": [
                    "정상 후보 URL 데이터베이스에서 일치하는 주소가 확인되었습니다.",
                    "정상 여부가 별도로 검증된 것은 아닙니다."
                ],
                "source": source
            }

    features = extract_features(normalized_url)
    risk_score, reasons = calculate_risk(features)

    if risk_score >= 30:
        status = "의심"
    else:
        status = "미확인"

    if not reasons:
        reasons.append(
            "데이터베이스에서 일치하는 주소를 찾지 못했습니다."
        )
        reasons.append(
            "현재 분석 기준에서 뚜렷한 의심 특징이 발견되지 않았습니다."
        )

    return {
        "url": url,
        "normalized_url": normalized_url,
        "status": status,
        "risk_score": risk_score,
        "reasons": reasons,
        "source": "URL 구조 분석"
    }
