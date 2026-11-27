from unittest.mock import patch

import pandas as pd
import pytest

from batch_analyzer import analyze_batch, get_batch_summary


def make_analysis(url, status="정상 후보", risk_score=0):
    return {
        "normalized_url": url,
        "status": status,
        "risk_score": risk_score,
        "reasons": ["테스트 판정"],
        "source": "테스트",
    }


def test_multiple_urls_and_trim():
    """여러 URL을 처리하고 앞뒤 공백을 제거하는지 확인."""
    dataframe = pd.DataFrame({
        "url": ["  https://example.com  ", "https://example.org"],
    })

    with patch(
        "batch_analyzer.analyze_url",
        side_effect=make_analysis,
    ) as mock_analyze:
        result = analyze_batch(dataframe, "url")

    assert len(result) == 2
    assert mock_analyze.call_count == 2

    assert [
        call.args[0] for call in mock_analyze.call_args_list
    ] == [
        "https://example.com",
        "https://example.org",
    ]

    assert result["status"].tolist() == ["정상 후보", "정상 후보"]


def test_empty_urls_are_unknown():
    """빈 값은 분석기를 호출하지 않고 미확인 처리하는지 확인."""
    dataframe = pd.DataFrame({
        "url": [None, "", "   ", float("nan")],
    })

    with patch("batch_analyzer.analyze_url") as mock_analyze:
        result = analyze_batch(dataframe, "url")

    mock_analyze.assert_not_called()

    assert len(result) == 4
    assert result["status"].tolist() == ["미확인"] * 4
    assert result["source"].tolist() == ["입력값 검증"] * 4


def test_error_does_not_stop_batch():
    """한 URL에서 오류가 나도 다음 URL을 처리하는지 확인."""
    dataframe = pd.DataFrame({
        "url": ["https://example.com", "https://example.org"],
    })

    with patch(
        "batch_analyzer.analyze_url",
        side_effect=[
            RuntimeError("테스트 오류"),
            make_analysis("https://example.org"),
        ],
    ) as mock_analyze:
        result = analyze_batch(dataframe, "url")

    assert mock_analyze.call_count == 2
    assert result["status"].tolist() == ["미확인", "정상 후보"]
    assert result.loc[0, "source"] == "분석 오류"
    assert "테스트 오류" in result.loc[0, "reasons"]


def test_existing_columns_are_preserved():
    """기존 열을 보존하고 결과 열의 중복을 방지하는지 확인."""
    dataframe = pd.DataFrame({
        "url": ["https://example.com"],
        "normalized_url": ["기존 URL"],
        "source": ["기존 출처"],
        "input_source": ["이미 존재하는 값"],
    })
    original = dataframe.copy(deep=True)

    with patch(
        "batch_analyzer.analyze_url",
        side_effect=make_analysis,
    ):
        result = analyze_batch(dataframe, "url")

    assert result.columns.is_unique
    assert result.loc[0, "input_normalized_url"] == "기존 URL"
    assert result.loc[0, "input_source"] == "이미 존재하는 값"
    assert result.loc[0, "input_source_2"] == "기존 출처"
    assert result.loc[0, "source"] == "테스트"

    # 함수 호출이 원본 데이터까지 변경하지 않는지 확인
    pd.testing.assert_frame_equal(dataframe, original)


def test_empty_dataframe():
    with pytest.raises(ValueError, match="분석할 데이터가 없습니다"):
        analyze_batch(pd.DataFrame({"url": []}), "url")


def test_missing_url_column():
    dataframe = pd.DataFrame({"other": ["value"]})

    with pytest.raises(ValueError, match="URL 컬럼이 존재하지 않습니다"):
        analyze_batch(dataframe, "url")


def test_duplicate_input_columns():
    dataframe = pd.DataFrame(
        [["https://example.com", "https://example.org"]],
        columns=["url", "url"],
    )

    with pytest.raises(ValueError, match="중복된 컬럼명"):
        analyze_batch(dataframe, "url")


def test_batch_summary():
    dataframe = pd.DataFrame({
        "status": ["악성", "악성", "의심", "정상 후보", "미확인"],
    })

    assert get_batch_summary(dataframe) == {
        "total": 5,
        "malicious": 2,
        "suspicious": 1,
        "normal_candidate": 1,
        "unknown": 1,
    }
