import streamlit as st
import pandas as pd

from history import get_history


STATUS_ORDER = ["악성", "의심", "정상 후보", "미확인"]

COLUMN_LABELS = {
    "id": "기록 번호",
    "url": "URL",
    "normalized_url": "정규화 URL",
    "status": "판정",
    "risk_score": "위험 점수",
    "source": "출처",
    "analyzed_at": "분석 시각(UTC)",
}


def prepare_history(history_df):
    """통계에 사용할 값을 정리합니다. 원본 DB는 변경하지 않습니다."""
    df = history_df.copy()

    df["status"] = (
        df["status"]
        .fillna("")
        .astype(str)
        .str.strip()
        .replace("", "미확인")
    )

    df["source"] = (
        df["source"]
        .fillna("")
        .astype(str)
        .str.strip()
        .replace("", "출처 미상")
    )

    df["risk_score"] = pd.to_numeric(
        df["risk_score"],
        errors="coerce",
    )

    # 통계 계산용: 0~100 범위 밖의 점수는 유효하지 않은 값으로 처리
    df["_valid_risk_score"] = df["risk_score"].where(
        df["risk_score"].between(0, 100)
    )

    # SQLite CURRENT_TIMESTAMP로 저장된 기존 시각은 UTC입니다.
    df["_analyzed_at"] = pd.to_datetime(
        df["analyzed_at"],
        errors="coerce",
        utc=True,
    )

    return df


def render_dashboard():
    st.subheader("분석 통계 대시보드")

    history_df = get_history(limit=None)

    if history_df.empty:
        st.info("아직 분석 기록이 없습니다. URL을 먼저 분석해 주세요.")
        return

    df = prepare_history(history_df)

    st.caption(
        f"전체 저장 기록: {len(df):,}건 · "
        "아래 통계와 다운로드에는 선택한 필터가 적용됩니다."
    )

    # ── 검색 및 필터 ──
    st.markdown("### 조회 조건")

    filter_col1, filter_col2 = st.columns(2)

    status_options = STATUS_ORDER + sorted(
        set(df["status"].unique()) - set(STATUS_ORDER)
    )

    with filter_col1:
        selected_statuses = st.multiselect(
            "판정 선택",
            options=status_options,
            default=status_options,
            key="dashboard_status_filter",
        )

    with filter_col2:
        source_options = sorted(df["source"].unique().tolist())

        selected_sources = st.multiselect(
            "출처 선택",
            options=source_options,
            default=source_options,
            key="dashboard_source_filter",
        )

    keyword = st.text_input(
        "URL 검색",
        placeholder="예: example.com",
        key="dashboard_url_keyword",
    ).strip()

    use_date_filter = st.checkbox(
        "기간 필터 사용",
        key="dashboard_use_date_filter",
    )

    start_date = None
    end_date = None

    if use_date_filter:
        valid_dates = df["_analyzed_at"].dropna()

        if valid_dates.empty:
            st.warning("유효한 분석 날짜가 없어 기간 필터를 사용할 수 없습니다.")
            return

        min_date = valid_dates.min().date()
        max_date = valid_dates.max().date()

        date_col1, date_col2 = st.columns(2)

        with date_col1:
            start_date = st.date_input(
                "시작일(UTC)",
                value=min_date,
                min_value=min_date,
                max_value=max_date,
                key="dashboard_start_date",
            )

        with date_col2:
            end_date = st.date_input(
                "종료일(UTC)",
                value=max_date,
                min_value=min_date,
                max_value=max_date,
                key="dashboard_end_date",
            )

        if start_date > end_date:
            st.error("시작일은 종료일보다 늦을 수 없습니다.")
            return

    filtered = df[
        df["status"].isin(selected_statuses)
        & df["source"].isin(selected_sources)
    ].copy()

    if keyword:
        url_match = (
            filtered["url"]
            .fillna("")
            .astype(str)
            .str.contains(keyword, case=False, regex=False)
        )

        normalized_match = (
            filtered["normalized_url"]
            .fillna("")
            .astype(str)
            .str.contains(keyword, case=False, regex=False)
        )

        filtered = filtered[url_match | normalized_match].copy()

    if use_date_filter:
        start_timestamp = pd.Timestamp(start_date, tz="UTC")
        end_exclusive = (
            pd.Timestamp(end_date, tz="UTC")
            + pd.Timedelta(days=1)
        )

        filtered = filtered[
            (filtered["_analyzed_at"] >= start_timestamp)
            & (filtered["_analyzed_at"] < end_exclusive)
        ].copy()

    if filtered.empty:
        st.info("선택한 조건에 해당하는 분석 기록이 없습니다.")
        return

    st.divider()

    # ── 요약 통계 ──
    st.markdown("### 선택 조건 분석 현황")

    counts = filtered["status"].value_counts()

    col1, col2, col3, col4, col5 = st.columns(5)

    col1.metric("전체 분석", f"{len(filtered):,}건")
    col2.metric("악성", f"{int(counts.get('악성', 0)):,}건")
    col3.metric("의심", f"{int(counts.get('의심', 0)):,}건")
    col4.metric("정상 후보", f"{int(counts.get('정상 후보', 0)):,}건")
    col5.metric("미확인", f"{int(counts.get('미확인', 0)):,}건")

    average_score = filtered["_valid_risk_score"].mean()
    unique_urls = (
        filtered["url"]
        .fillna("")
        .astype(str)
        .str.strip()
        .replace("", pd.NA)
        .nunique()
    )

    risk_count = filtered["status"].isin(["악성", "의심"]).sum()
    risk_ratio = risk_count / len(filtered) * 100

    extra_col1, extra_col2, extra_col3 = st.columns(3)

    extra_col1.metric(
        "평균 위험 점수",
        "계산 불가" if pd.isna(average_score) else f"{average_score:.1f}점",
    )
    extra_col2.metric("고유 URL", f"{unique_urls:,}개")
    extra_col3.metric("악성·의심 비율", f"{risk_ratio:.1f}%")

    invalid_scores = int(filtered["_valid_risk_score"].isna().sum())

    if invalid_scores:
        st.caption(
            f"누락되었거나 0~100 범위를 벗어난 위험 점수 "
            f"{invalid_scores:,}건은 평균과 점수 분포에서 제외했습니다."
        )

    other_status_count = int(
        (~filtered["status"].isin(STATUS_ORDER)).sum()
    )

    if other_status_count:
        st.caption(
            f"기본 4개 판정 외의 기록 {other_status_count:,}건도 "
            "전체 분석 건수와 아래 판정 분포에 포함됩니다."
        )

    st.divider()

    # ── 판정 결과 분포 ──
    st.markdown("### 판정 결과 분포")

    display_statuses = STATUS_ORDER + sorted(
        set(filtered["status"].unique()) - set(STATUS_ORDER)
    )

    status_counts = (
        filtered["status"]
        .value_counts()
        .reindex(display_statuses, fill_value=0)
        .rename("분석 건수")
    )

    st.bar_chart(status_counts)

    # ── 위험 점수 분포 ──
    st.markdown("### 위험 점수 분포")

    # right=False: [0, 1), [1, 30), ... [80, 101)
    risk_bins = pd.cut(
        filtered["_valid_risk_score"],
        bins=[0, 1, 30, 60, 80, 101],
        labels=["0점 이상 1점 미만", "1~29점", "30~59점", "60~79점", "80~100점"],
        right=False,
    )

    risk_counts = (
        risk_bins.value_counts()
        .sort_index()
        .rename("분석 건수")
    )

    st.bar_chart(risk_counts)
    st.caption("구간 경계: 0 이상 1 미만 / 1 이상 30 미만 / "
               "30 이상 60 미만 / 60 이상 80 미만 / 80 이상 100 이하")

    # ── 출처별 현황 ──
    st.markdown("### 데이터 출처별 분석 현황")

    source_counts = (
        filtered["source"]
        .value_counts()
        .rename("분석 건수")
    )

    st.bar_chart(source_counts)

    # ── 일별 분석 추이 ──
    st.markdown("### 일별 분석 추이")

    dated_records = filtered.dropna(subset=["_analyzed_at"])

    if dated_records.empty:
        st.info("날짜를 확인할 수 있는 기록이 없습니다.")
    else:
        daily_counts = (
            dated_records
            .set_index("_analyzed_at")
            .resample("D")
            .size()
        )

        daily_counts.index = daily_counts.index.strftime("%Y-%m-%d")
        daily_counts.index.name = "분석일(UTC)"
        daily_counts.name = "분석 건수"

        st.line_chart(daily_counts)

    st.divider()

    # ── 기록 조회 및 CSV 다운로드 ──
    st.markdown("### 분석 기록")
    st.caption(
        f"조건에 맞는 기록: {len(filtered):,}건 · 최신 저장 순으로 표시합니다."
    )

    display_limit = st.selectbox(
        "화면에 표시할 기록 수",
        options=[20, 50, 100, 500],
        key="dashboard_display_limit",
    )

    export_df = filtered[list(COLUMN_LABELS)].rename(
        columns=COLUMN_LABELS
    )

    st.dataframe(
        export_df.head(display_limit),
        use_container_width=True,
        hide_index=True,
    )

    # Excel에서 한글이 깨지지 않도록 UTF-8 BOM을 사용합니다.
    csv_data = export_df.to_csv(index=False).encode("utf-8-sig")

    st.download_button(
        label="조회 결과 전체 CSV 다운로드",
        data=csv_data,
        file_name="analysis_history.csv",
        mime="text/csv",
        key="dashboard_csv_download",
    )
