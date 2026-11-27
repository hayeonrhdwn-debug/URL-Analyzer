import io
import pandas as pd
import streamlit as st

from batch_analyzer import analyze_batch, get_batch_summary
from dashboard import render_dashboard
from history import (
    get_history,
    get_history_summary,
    initialize_history,
    save_analysis,
)
from url_analyzer import analyze_url


def _extract_analysis_payload(raw_result):
    """analyze_url 반환 형식이 dict 또는 튜플이어도 일관된 형태로 정규화한다."""
    if isinstance(raw_result, tuple):
        payload = raw_result[0] if raw_result else {}
    else:
        payload = raw_result

    if not isinstance(payload, dict):
        return {"raw": payload}
    return payload


def _render_single_result(url: str, payload: dict):
    """단일 URL 분석 결과를 한 곳에서 일관되게 렌더링한다."""
    with st.container(border=True):
        st.subheader("분석 결과")
        st.caption(f"대상 URL: {url}")

        risk_score = payload.get("risk_score", payload.get("score", "N/A"))
        verdict = payload.get(
            "verdict", payload.get("status", payload.get("label", "분석 완료"))
        )
        confidence = payload.get("confidence", payload.get("confidence_score", "-"))

        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("위험도 / 점수", risk_score)
        with col2:
            st.metric("판정 결과", verdict)
        with col3:
            st.metric("신뢰도", confidence)

        details = {
            k: v
            for k, v in payload.items()
            if k
            not in {
                "risk_score",
                "score",
                "verdict",
                "status",
                "label",
                "confidence",
                "confidence_score",
            }
        }
        if details:
            with st.expander("상세 분석 정보 보기", expanded=False):
                st.json(details)


def _render_single_url_tab():
    """단일 URL 입력 및 분석 결과 탭."""
    st.header("단일 URL 분석")

    if "single_analysis_result" not in st.session_state:
        st.session_state.single_analysis_result = None

    with st.container(border=True):
        url_input = st.text_input(
            "분석할 URL을 입력하세요",
            placeholder="https://example.com",
            key="single_url_input",
        )
        analyze_clicked = st.button(
            "URL 분석하기", type="primary", key="single_analyze_btn"
        )

    if analyze_clicked:
        cleaned_url = url_input.strip()
        if not cleaned_url:
            st.warning("분석할 URL을 먼저 입력해 주세요.")
        else:
            try:
                with st.spinner("URL을 분석하는 중입니다..."):
                    raw_result = analyze_url(cleaned_url)
                payload = _extract_analysis_payload(raw_result)
                record = {"url": cleaned_url, **payload}
                save_analysis(record)
                st.session_state.single_analysis_result = {
                    "url": cleaned_url,
                    "payload": payload,
                }
            except Exception as exc:
                st.session_state.single_analysis_result = None
                st.error(f"URL 분석 중 오류가 발생했습니다: {exc}")

    saved = st.session_state.single_analysis_result
    if saved:
        _render_single_result(saved["url"], saved["payload"])


def _render_batch_tab():
    """일괄 URL 분석 탭."""
    st.header("일괄 URL 분석")

    uploaded_file = st.file_uploader(
        "URL 목록 CSV 파일 업로드", type=["csv"], key="batch_csv_uploader"
    )
    raw_urls_text = st.text_area(
        "또는 URL을 한 줄에 하나씩 입력",
        placeholder="https://example.com\nhttps://example.org",
        height=120,
        key="batch_urls_textarea",
    )

    df = None
    url_column = "url"

    if uploaded_file is not None:
        df = pd.read_csv(io.BytesIO(uploaded_file.getvalue()))
        url_column = st.selectbox(
            "URL 컬럼 선택", options=list(df.columns), key="batch_url_col"
        )
    elif raw_urls_text.strip():
        urls = [line.strip() for line in raw_urls_text.splitlines() if line.strip()]
        df = pd.DataFrame({url_column: urls})

    if st.button("일괄 분석 시작", type="primary", key="batch_analyze_btn"):
        if df is None or df.empty:
            st.warning("CSV 파일을 업로드하거나 URL을 입력해 주세요.")
        else:
            try:
                with st.spinner("일괄 분석을 진행하는 중입니다..."):
                    result_df = analyze_batch(df, url_column)
                    summary = get_batch_summary(result_df)

                if isinstance(summary, dict) and summary:
                    cols = st.columns(min(len(summary), 4))
                    for idx, (k, v) in enumerate(summary.items()):
                        with cols[idx % len(cols)]:
                            st.metric(str(k), v)

                st.dataframe(result_df, use_container_width=True)
            except Exception as exc:
                st.error(f"일괄 분석 중 오류가 발생했습니다: {exc}")


def _render_history_tab():
    """분석 기록 탭."""
    st.header("분석 기록")

    summary = get_history_summary()
    if isinstance(summary, dict) and summary:
        cols = st.columns(min(len(summary), 4))
        for idx, (k, v) in enumerate(summary.items()):
            with cols[idx % len(cols)]:
                st.metric(str(k), v)

    limit = st.slider("표시할 기록 수", min_value=10, max_value=200, value=100, step=10)
    records = get_history(limit=limit)

    if not records:
        st.info("저장된 분석 기록이 없습니다.")
    else:
        st.dataframe(records, use_container_width=True)


def main():
    st.set_page_config(page_title="URL Analyzer", page_icon="🔍", layout="wide")
    initialize_history()
    st.title("🔍 URL Analyzer")

    tab1, tab2, tab3, tab4 = st.tabs(
        ["단일 URL 분석", "일괄 분석", "대시보드", "분석 기록"]
    )

    with tab1:
        _render_single_url_tab()

    with tab2:
        _render_batch_tab()

    with tab3:
        render_dashboard()

    with tab4:
        _render_history_tab()
def _render_history_tab():
    """분석 기록 탭."""
    st.header("분석 기록")

    summary = get_history_summary()
    if isinstance(summary, dict) and summary:
        cols = st.columns(min(len(summary), 4))
        for idx, (k, v) in enumerate(summary.items()):
            with cols[idx % len(cols)]:
                st.metric(str(k), v)

    limit = st.slider("표시할 기록 수", min_value=10, max_value=200, value=100, step=10)
    records = get_history(limit=limit)

    is_empty = records is None or (
        records.empty if isinstance(records, pd.DataFrame) else len(records) == 0
    )
    if is_empty:
        st.info("저장된 분석 기록이 없습니다.")
    else:
        st.dataframe(records, use_container_width=True)

if __name__ == "__main__":
    main()