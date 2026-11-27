
import pandas as pd

from url_analyzer import analyze_url


def analyze_batch(dataframe, url_column):
    if dataframe.empty:
        raise ValueError("분석할 데이터가 없습니다.")

    if url_column not in dataframe.columns:
        raise ValueError("선택한 URL 컬럼이 존재하지 않습니다.")

    results = []

    for url in dataframe[url_column]:
        if pd.isna(url) or not str(url).strip():
            result = {
                "normalized_url": "",
                "status": "미확인",
                "risk_score": 0,
                "reasons": "URL 값이 비어 있습니다.",
                "source": "입력값 검증"
            }
        else:
            analysis = analyze_url(str(url))

            result = {
                "normalized_url": analysis["normalized_url"],
                "status": analysis["status"],
                "risk_score": analysis["risk_score"],
                "reasons": " / ".join(analysis["reasons"]),
                "source": analysis["source"]
            }

        results.append(result)

    result_df = dataframe.copy()

    analysis_df = pd.DataFrame(results)

    return pd.concat(
        [result_df.reset_index(drop=True), analysis_df],
        axis=1
    )


def get_batch_summary(result_df):
    return {
        "total": len(result_df),
        "malicious": int((result_df["status"] == "악성").sum()),
        "suspicious": int((result_df["status"] == "의심").sum()),
        "normal_candidate": int((result_df["status"] == "정상 후보").sum()),
        "unknown": int((result_df["status"] == "미확인").sum())
    }
