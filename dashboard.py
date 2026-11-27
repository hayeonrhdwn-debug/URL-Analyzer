
import streamlit as st
import pandas as pd

from history import get_history, get_history_summary


def render_dashboard():
    st.subheader("분석 통계 대시보드")

    history_df = get_history(limit=1000000)

    if history_df.empty:
        st.info("아직 분석 기록이 없습니다. URL을 먼저 분석해 주세요.")
        return

    summary = get_history_summary()

    st.markdown("### 전체 분석 현황")

    col1, col2, col3, col4, col5 = st.columns(5)

    col1.metric("전체 분석", f"{summary['total']:,}건")
    col2.metric("악성", f"{summary['malicious']:,}건")
    col3.metric("의심", f"{summary['suspicious']:,}건")
    col4.metric("정상 후보", f"{summary['normal_candidate']:,}건")
    col5.metric("미확인", f"{summary['unknown']:,}건")

    st.divider()

    st.markdown("### 판정 결과 분포")

    status_order = ["악성", "의심", "정상 후보", "미확인"]

    status_counts = (
        history_df["status"]
        .value_counts()
        .reindex(status_order, fill_value=0)
    )

    st.bar_chart(status_counts)

    st.markdown("### 위험 점수 분포")

    risk_bins = pd.cut(
        history_df["risk_score"],
        bins=[-1, 0, 29, 59, 79, 100],
        labels=["0점", "1~29점", "30~59점", "60~79점", "80~100점"]
    )

    risk_counts = risk_bins.value_counts().sort_index()

    st.bar_chart(risk_counts)

    st.markdown("### 데이터 출처별 분석 현황")

    source_counts = (
        history_df["source"]
        .fillna("출처 미상")
        .replace("", "출처 미상")
        .value_counts()
    )

    st.bar_chart(source_counts)

    st.divider()

    st.markdown("### 최근 분석 기록")

    st.dataframe(
        history_df.head(20),
        use_container_width=True,
        hide_index=True
    )
