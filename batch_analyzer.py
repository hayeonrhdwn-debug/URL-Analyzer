import pandas as pd

from url_analyzer import analyze_url


def analyze_batch(dataframe, url_column):
    """URL을 일괄 분석하고 원본 데이터에 분석 결과를 추가한다."""

    # 입력 데이터 검증
    # 기존 테스트에서 확인하는 예외 메시지를 그대로 유지한다.
    if dataframe.empty:
        raise ValueError("분석할 데이터가 없습니다.")

    if url_column not in dataframe.columns:
        raise ValueError("선택한 URL 컬럼이 존재하지 않습니다.")

    if not dataframe.columns.is_unique:
        raise ValueError("입력 데이터에 중복된 컬럼명이 있습니다.")

    results = []

    for url in dataframe[url_column]:
        cleaned_url = "" if pd.isna(url) else str(url).strip()

        # 빈 URL과 분석 실패 시 공통으로 사용하는 기본 결과
        result = {
            "normalized_url": cleaned_url,
            "status": "미확인",
            "risk_score": 0,
            "reasons": "URL 값이 비어 있습니다.",
            "source": "입력값 검증",
        }

        if cleaned_url:
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
                # 개별 URL의 오류가 전체 분석을 중단하지 않게 한다.
                result.update({
                    "reasons": (
                        "URL 분석 중 오류가 발생했습니다. "
                        f"({type(error).__name__}: {error})"
                    ),
                    "source": "분석 오류",
                })

        # 성공, 빈 값, 오류 모두 URL 하나당 한 번만 추가한다.
        results.append(result)

    result_df = dataframe.copy().reset_index(drop=True)
    analysis_df = pd.DataFrame(results)

    # 원본 컬럼과 분석 결과 컬럼의 이름 충돌을 한 곳에서 처리한다.
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
    status_counts = result_df["status"].value_counts()

    return {
        "total": len(result_df),
        "malicious": int(status_counts.get("악성", 0)),
        "suspicious": int(status_counts.get("의심", 0)),
        "normal_candidate": int(status_counts.get("정상 후보", 0)),
        "unknown": int(status_counts.get("미확인", 0)),
    }
