import pandas as pd

from url_analyzer import analyze_url


def _analyze_single_url(url):
    """URL 하나를 분석한다. 빈 값과 분석 오류는 미확인으로 반환한다."""
    cleaned_url = "" if pd.isna(url) else str(url).strip()

    if not cleaned_url:
        return {
            "normalized_url": "",
            "status": "미확인",
            "risk_score": 0,
            "reasons": "URL 값이 비어 있습니다.",
            "source": "입력값 검증",
        }

    try:
        analysis = analyze_url(cleaned_url)

        return {
            "normalized_url": analysis["normalized_url"],
            "status": analysis["status"],
            "risk_score": analysis["risk_score"],
            "reasons": " / ".join(analysis["reasons"]),
            "source": analysis["source"],
        }

    except Exception as error:
        # 한 URL의 분석 실패가 전체 일괄 분석을 중단하지 않게 한다.
        return {
            "normalized_url": cleaned_url,
            "status": "미확인",
            "risk_score": 0,
            "reasons": (
                "URL 분석 중 오류가 발생했습니다. "
                f"({type(error).__name__}: {error})"
            ),
            "source": "분석 오류",
        }


def _rename_conflicting_columns(dataframe, analysis_columns):
    """분석 결과와 이름이 겹치는 원본 컬럼을 이름 변경하여 보존한다."""
    used_columns = set(dataframe.columns) | set(analysis_columns)
    rename_map = {}

    for column in analysis_columns:
        if column not in dataframe.columns:
            continue

        base_name = f"input_{column}"
        new_name = base_name
        suffix = 2

        while new_name in used_columns:
            new_name = f"{base_name}_{suffix}"
            suffix += 1

        rename_map[column] = new_name
        used_columns.add(new_name)

    return dataframe.rename(columns=rename_map)


def analyze_batch(dataframe, url_column):
    """입력 데이터의 URL을 일괄 분석하고 원본과 결과를 합쳐 반환한다."""
    if dataframe.empty:
        raise ValueError("분석할 데이터가 없습니다.")

    if url_column not in dataframe.columns:
        raise ValueError("선택한 URL 컬럼이 존재하지 않습니다.")

    if not dataframe.columns.is_unique:
        raise ValueError("입력 데이터에 중복된 컬럼명이 있습니다.")

    results = []

    for url in dataframe[url_column]:
        result = _analyze_single_url(url)

        # URL 하나당 정확히 한 번만 결과를 추가한다.
        results.append(result)

    analysis_df = pd.DataFrame(results)
    original_df = dataframe.copy().reset_index(drop=True)

    original_df = _rename_conflicting_columns(
        original_df,
        analysis_df.columns,
    )

    return pd.concat([original_df, analysis_df], axis=1)


def get_batch_summary(result_df):
    """상태별 개수를 한 번 집계하고 요약 정보를 반환한다."""
    status_counts = result_df["status"].value_counts()

    return {
        "total": len(result_df),
        "malicious": int(status_counts.get("악성", 0)),
        "suspicious": int(status_counts.get("의심", 0)),
        "normal_candidate": int(status_counts.get("정상 후보", 0)),
        "unknown": int(status_counts.get("미확인", 0)),
    }
