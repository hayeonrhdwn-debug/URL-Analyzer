
from url_analyzer import (
    analyze_url,
    normalize_url,
    extract_features,
    calculate_risk
)


def test_normalize_url():
    assert normalize_url("https://example.com") == "https://example.com/"


def test_malicious_url_detection():
    result = analyze_url("http://c15.zty5.show")

    assert result["status"] == "악성"
    assert result["risk_score"] == 100
    assert result["source"] == "KISA"


def test_ip_address_detection():
    result = analyze_url("http://192.168.1.100/login")

    assert result["status"] == "의심"
    assert result["risk_score"] == 35


def test_unknown_url():
    result = analyze_url("https://example.com")

    assert result["status"] == "미확인"
    assert result["risk_score"] == 0


def test_invalid_url():
    result = analyze_url("")

    assert result["status"] == "미확인"
    assert result["source"] == "입력값 검증"


def test_feature_extraction():
    features = extract_features("http://192.168.1.100/login")

    assert features["has_ip"] is True
    assert features["uses_https"] is False


def test_risk_calculation():
    features = extract_features("http://192.168.1.100/login")
    score, reasons = calculate_risk(features)

    assert score == 35
    assert len(reasons) >= 2
