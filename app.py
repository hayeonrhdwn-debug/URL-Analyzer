import streamlit as st
import pandas as pd

from data_loader import load_dataset, get_dataset_summary
from url_analyzer import analyze_url
from batch_analyzer import analyze_batch, get_batch_summary
from history import save_analysis, get_history, get_history_summary
from dashboard import render_dashboard


st.set_page_config(
    page_title="URL 피싱 분석 시스템",
    page_icon="🛡️",
    layout="wide"
)


@st.cache_data
def get_dataset():
    return load_dataset()


@st.cache_data
def get_summary():
    return get_dataset_summary(get_dataset())


st.title("🛡️ URL 피싱 분석 시스템")
st.write("URL 데이터베이스와 구조 분석을 활용한 피싱 URL 탐지 시스템")

try:
    dataset = get_dataset()
    summary = get_summary()

    col1, col2, col3 = st.columns(3)

    col1.metric("전체 데이터", f"{summary['total']:,}건")
    col2.metric("악성 URL", f"{summary['malicious']:,}건")
    col3.metric("정상 후보 URL", f"{summary['normal_candidate']:,}건")

    st.divider()

    tab1, tab2, tab3, tab4 = st.tabs([
        "단일 URL 분석",
        "CSV 일괄 분석",
        "분석 기록",
        "통계 대시보드"
    ])

    with tab1:
        st.subheader("URL 분석")
        st.caption("분석할 웹 주소를 입력하면 위험도와 세부 항목을 확인할 수 있습니다.")

        # 1. 입력 영역 (가로로 나란히 배치)
        col_input, col_btn = st.columns([4, 1], vertical_alignment="bottom")
        with col_input:
            url = st.text_input(
                "분석할 URL을 입력하세요.",
                placeholder="https://example.com",
                key="single_url",
            )
        with col_btn:
            clicked = st.button("URL 분석하기", type="primary", use_container_width=True)

        if clicked:
            cleaned_url = url.strip()
            if not cleaned_url:
                st.warning("URL을 입력해 주세요.")
            else:
                with st.spinner("URL을 분석하는 중..."):
                    result = analyze_url(cleaned_url)
                    save_analysis(result)
                    st.session_state["single_result"] = result

        # 2. 분석 결과 영역
        if "single_result" in st.session_state:
            result = st.session_state["single_result"]

            st.divider()
            st.subheader("분석 결과")

            if isinstance(result, dict):
                with st.container(border=True):
                    m1, m2, m3 = st.columns(3)
                    m1.metric("위험 점수", result.get("score", "-"))
                    m2.metric("판정 결과", result.get("status", result.get("risk", "-")))
                    m3.metric(
                        "검사 항목 수",
                        len(result.get("reasons", [])) if isinstance(result.get("reasons"), list) else "-",
                    )

                    if result.get("normalized_url"):
                        st.markdown(f"**정규화된 URL:** `{result['normalized_url']}`")

                    reasons = result.get("reasons")
                    if reasons:
                        st.markdown("**세부 분석 내용**")
                        if isinstance(reasons, list):
                            for item in reasons:
                                st.markdown(f"- {item}")
                        else:
                            st.write(reasons)

                with st.expander("원본 데이터 보기"):
                    st.json(result)
            else:
                with st.container(border=True):
                    st.write(result)

    with tab2:
        st.subheader("CSV 파일 일괄 분석")

        st.write("URL이 포함된 CSV 파일을 업로드하여 여러 주소를 한 번에 분석합니다.")

        uploaded_file = st.file_uploader(
            "CSV 파일 선택",
            type=["csv"],
            key="batch_file"
        )

        if uploaded_file is not None:
            try:
                uploaded_df = pd.read_csv(
                    uploaded_file,
                    encoding="utf-8-sig"
                )

                if uploaded_df.empty:
                    st.warning("CSV 파일에 분석할 데이터가 없습니다.")
                else:
                    st.write("**업로드 데이터 미리보기**")
                    st.dataframe(
                        uploaded_df.head(10),
                        use_container_width=True
                    )

                    url_column = st.selectbox(
                        "URL이 들어 있는 열을 선택하세요.",
                        options=uploaded_df.columns
                    )

                    if st.button("전체 URL 분석하기", type="primary"):
                        with st.spinner("URL을 분석하고 있습니다..."):
                            result_df = analyze_batch(
                                uploaded_df,
                                url_column
                            )

                            for _, row in result_df.iterrows():
                                save_analysis({
                                    "url": str(row[url_column]),
                                    "normalized_url": row["normalized_url"],
                                    "status": row["status"],
                                    "risk_score": int(row["risk_score"]),
                                    "source": row["source"]
                                })

                            st.session_state["batch_result"] = result_df
                            st.success("분석 결과가 기록에 저장되었습니다.")

                if "batch_result" in st.session_state:
                    result_df = st.session_state["batch_result"]
                    batch_summary = get_batch_summary(result_df)

                    st.divider()
                    st.subheader("일괄 분석 결과")

                    result_col1, result_col2, result_col3, result_col4, result_col5 = st.columns(5)

                    result_col1.metric("전체 분석", f"{batch_summary['total']:,}건")
                    result_col2.metric("악성", f"{batch_summary['malicious']:,}건")
                    result_col3.metric("의심", f"{batch_summary['suspicious']:,}건")
                    result_col4.metric("정상 후보", f"{batch_summary['normal_candidate']:,}건")
                    result_col5.metric("미확인", f"{batch_summary['unknown']:,}건")

                    st.dataframe(
                        result_df,
                        use_container_width=True
                    )

                    csv_data = result_df.to_csv(
                        index=False
                    ).encode("utf-8-sig")

                    st.download_button(
                        "분석 결과 CSV 다운로드",
                        data=csv_data,
                        file_name="url_analysis_result.csv",
                        mime="text/csv"
                    )

                    st.caption("정상 후보는 안전성이 독립적으로 검증된 결과가 아닙니다.")

            except UnicodeDecodeError:
                st.error("CSV 인코딩을 읽을 수 없습니다. UTF-8 형식으로 저장한 파일을 사용해 주세요.")
            except Exception as error:
                st.error(f"CSV 처리 중 오류가 발생했습니다: {error}")

    with tab3:
        st.subheader("URL 분석 기록")

        history_summary = get_history_summary()

        history_col1, history_col2, history_col3, history_col4, history_col5 = st.columns(5)

        history_col1.metric("전체 기록", f"{history_summary['total']:,}건")
        history_col2.metric("악성", f"{history_summary['malicious']:,}건")
        history_col3.metric("의심", f"{history_summary['suspicious']:,}건")
        history_col4.metric("정상 후보", f"{history_summary['normal_candidate']:,}건")
        history_col5.metric("미확인", f"{history_summary['unknown']:,}건")

        history_df = get_history()

        if history_df.empty:
            st.info("아직 저장된 분석 기록이 없습니다.")
        else:
            st.dataframe(
                history_df,
                use_container_width=True,
                hide_index=True
            )

            history_csv = history_df.to_csv(
                index=False
            ).encode("utf-8-sig")

            st.download_button(
                "분석 기록 CSV 다운로드",
                data=history_csv,
                file_name="analysis_history.csv",
                mime="text/csv"
            )

    with tab4:
        render_dashboard()

    st.divider()

    st.subheader("데이터 출처별 현황")
    st.bar_chart(summary["sources"])

    st.caption(
        "위험 점수는 확률이 아닌 규칙 기반 점수입니다. "
        "미확인 결과가 안전을 보장하지는 않습니다."
    )

except Exception as error:
    st.error(f"프로그램 실행 중 오류가 발생했습니다: {error}")