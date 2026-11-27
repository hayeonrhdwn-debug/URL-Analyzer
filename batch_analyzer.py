import pandas as pd

from url_analyzer import analyze_url


def analyze_batch(dataframe, url_column):
    """URL 열을 일괄 분석하고 원본 데이터에 분석 결과를 추가한다."""
    if dataframe.empty:
        raise ValueError("분석할 데이터가 없습니다.")

    if url_column not in dataframe.columns:
        raise ValueError("선택한 URL 컬럼이 존재하지 않습니다.")

    if not dataframe.columns.is_unique:
        raise ValueError("입력 데이터에 중복된 컬럼명이 있습니다.")

    results = []

    for url in dataframe[url_column]:
        if pd.isna(url) or not str(url).strip():
            result = {
                "normalized_url": "",
                "status": "미확인",
                "risk_score": 0,
                "reasons": "URL 값이 비어 있습니다.",
                "source": "입력값 검증",
            }
        else:
            cleaned_url = str(url).strip()

            try:
                analysis = analyze_url(cleaned_url)

                result = {
                    "normalized_url": analysis["normalized_url"],
                    "status": analysis["status"],
                    "risk_score": analysis["risk_score"],
                    "reasons": " / ".join(analysis["reasons"]),
                    "source": analysis["source"],
                }

            except Exception as error:
                # 한 행의 분석 오류가 전체 배치를 중단하지 않도록 한다.
                result = {
                    "normalized_url": cleaned_url,
                    "status": "미확인",
                    "risk_score": 0,
                    "reasons": (
                        f"URL 분석 중 오류가 발생했습니다. "
                        f"({type(error).__name__}: {error})"
                    ),
                    "source": "분석 오류",
                }

        results.append(result)

    result_df = dataframe.copy().reset_index(drop=True)
    analysis_df = pd.DataFrame(results)

    # 분석 결과와 이름이 겹치는 원본 열은 input_ 접두어로 보존한다.
    # 해당 이름도 이미 존재하면 숫자를 붙여 중복을 방지한다.
    used_columns = set(result_df.columns) | set(analysis_df.columns)
    rename_map = {}

    for column in analysis_df.columns:
        if column not in result_df.columns:
            continue

        base_name = f"input_{column}"
        new_name = base_name
        suffix = 2

        while new_name in used_columns:
            new_name = f"{base_name}_{suffix}"
            suffix += 1

        rename_map[column] = new_name
        used_columns.add(new_name)

    result_df = result_df.rename(columns=rename_map)

    return pd.concat([result_df, analysis_df], axis=1)


def get_batch_summary(result_df):
    """분석 결과의 상태별 개수를 반환한다."""
    return {
        "total": len(result_df),
        "malicious": int((result_df["status"] == "악성").sum()),
        "suspicious": int((result_df["status"] == "의심").sum()),
        "normal_candidate": int(
            (result_df["status"] == "정상 후보").sum()
        ),
        "unknown": int((result_df["status"] == "미확인").sum()),
    }
