
from pathlib import Path

import pandas as pd


BASE_DIR = Path(__file__).resolve().parent
DATA_PATH = BASE_DIR / "data" / "urlshield_training_final.csv"

REQUIRED_COLUMNS = [
    "original_url",
    "normalized_url",
    "domain",
    "label",
    "source",
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "subdomain_count",
    "digit_count",
    "special_char_count",
    "has_ip",
    "uses_https",
    "has_at",
    "has_hyphen",
    "has_double_slash",
    "has_port",
    "source_date_added"
]


def load_dataset():
    if not DATA_PATH.exists():
        raise FileNotFoundError(
            f"데이터 파일을 찾을 수 없습니다: {DATA_PATH}"
        )

    df = pd.read_csv(DATA_PATH, low_memory=False)

    missing_columns = [
        column for column in REQUIRED_COLUMNS
        if column not in df.columns
    ]

    if missing_columns:
        raise ValueError(
            f"필수 컬럼이 없습니다: {missing_columns}"
        )

    df["label"] = pd.to_numeric(
        df["label"], errors="raise"
    ).astype(int)

    return df


def find_url(normalized_url, dataset):
    matched = dataset[
        dataset["normalized_url"] == normalized_url
    ]

    if matched.empty:
        return None

    return matched.iloc[0].to_dict()


def get_label_name(label):
    if label == 1:
        return "악성"

    if label == 0:
        return "정상 후보"

    return "미확인"


def get_dataset_summary(dataset):
    return {
        "total": len(dataset),
        "malicious": int((dataset["label"] == 1).sum()),
        "normal_candidate": int((dataset["label"] == 0).sum()),
        "sources": dataset["source"].value_counts().to_dict()
    }
