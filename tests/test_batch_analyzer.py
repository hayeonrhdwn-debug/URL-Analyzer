
import pandas as pd
import pytest

from batch_analyzer import analyze_batch, get_batch_summary


def test_batch_analysis():
    df = pd.DataFrame({
        "original_url": [
            "http://192.168.1.100/login",
            None,
            ""
        ]
    })

    result = analyze_batch(df, "original_url")

    assert len(result) == 3
    assert result.iloc[0]["status"] == "의심"
    assert result.iloc[1]["status"] == "미확인"
    assert result.iloc[2]["status"] == "미확인"


def test_missing_url_column():
    df = pd.DataFrame({"name": ["example"]})

    with pytest.raises(ValueError):
        analyze_batch(df, "original_url")


def test_empty_dataframe():
    df = pd.DataFrame(columns=["original_url"])

    with pytest.raises(ValueError):
        analyze_batch(df, "original_url")


def test_batch_summary():
    df = pd.DataFrame({
        "status": ["악성", "의심", "미확인", "정상 후보"]
    })

    summary = get_batch_summary(df)

    assert summary["total"] == 4
    assert summary["malicious"] == 1
    assert summary["suspicious"] == 1
    assert summary["unknown"] == 1
    assert summary["normal_candidate"] == 1
