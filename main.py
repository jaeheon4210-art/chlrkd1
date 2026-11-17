import json
import os
import re
import pandas as pd
import plotly.express as px
import streamlit as st

# 1. 페이지 기본 설정
st.set_page_config(
    page_title="사이버보안 URL 데이터 탐색 대시보드",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ 범용 생성형 AI는 정말 악성 URL과 정상 URL을 구별할 수 있을까?")
st.markdown("**4차시: 데이터 전처리(D) 및 탐색적 데이터 분석(EDA)** | 출처: 한국인터넷진흥원(KISA) 사이버보안 AI데이터셋")
st.divider()

# ---------------------------------------------------------
# 2. 데이터 불러오기 함수 (JSON / CSV 자동 지원)
# ---------------------------------------------------------
def load_raw_data(uploaded_file):
    if uploaded_file is not None:
        filename = uploaded_file.name.lower()
        if filename.endswith(".csv"):
            return pd.read_csv(uploaded_file)
        elif filename.endswith(".json"):
            raw = json.load(uploaded_file)
            if isinstance(raw, list):
                return pd.json_normalize(raw)
            elif isinstance(raw, dict):
                # KISA JSON 내부에 data, items, annotations 등 리스트 키가 있는 경우 자동 탐색
                for key, val in raw.items():
                    if isinstance(val, list) and len(val) > 0:
                        return pd.json_normalize(val)
                return pd.json_normalize(raw)
    
    # 업로드 파일이 없을 경우 로컬 data 폴더 확인
    for path in ["data/kisa_data.json", "data/kisa_data.csv", "kisa_data.json", "kisa_data.csv"]:
        if os.path.exists(path):
            if path.endswith(".csv"):
                return pd.read_csv(path)
            else:
                with open(path, "r", encoding="utf-8") as f:
                    raw = json.load(f)
                if isinstance(raw, list):
                    return pd.json_normalize(raw)
                for key, val in raw.items():
                    if isinstance(val, list) and len(val) > 0:
                        return pd.json_normalize(val)
    return None

# 사이드바: 데이터 업로드 및 열 설정
st.sidebar.header("📂 데이터 설정")
uploaded = st.sidebar.file_uploader("KISA 데이터 파일 업로드 (JSON 또는 CSV)", type=["json", "csv"])
df_raw = load_raw_data(uploaded)

if df_raw is None:
    st.warning("👈 왼쪽 사이드바에서 공공데이터포털(KISA)에서 내려받은 JSON 또는 CSV 파일을 업로드해 주세요.")
    st.info("💡 팁: GitHub 저장소의 `data/kisa_data.json` 경로에 파일을 넣어두면 업로드 없이도 자동 실행됩니다.")
    st.stop()

# URL 열과 라벨 열 자동 추정 및 선택
cols = list(df_raw.columns)
default_url_idx = next((i for i, c in enumerate(cols) if any(k in c.lower() for k in ["url", "uri", "domain", "link", "주소"])), 0)
default_lbl_idx = next((i for i, c in enumerate(cols) if any(k in c.lower() for k in ["label", "type", "class", "mal", "악성", "유형", "구분"])), min(1, len(cols)-1))

url_col = st.sidebar.selectbox("URL(웹 주소) 열 선택", cols, index=default_url_idx)
label_col = st.sidebar.selectbox("정답(정상/악성) 열 선택", cols, index=default_lbl_idx)

# ---------------------------------------------------------
# 3. [체크리스트 1] 원본 데이터 개요 (행·열 수, 자료형, 빈 값 개수)
# ---------------------------------------------------------
st.header("1. 원본 데이터 개요 (전처리 전)")
c1, c2, c3 = st.columns(3)
c1.metric("원본 행 수", f"{df_raw.shape[0]:,} 행")
c2.metric("원본 열 수", f"{df_raw.shape[1]:,} 열")
c3.metric("전체 빈 값(결측치) 수", f"{int(df_raw.isna().sum().sum()):,} 개")

overview_df = pd.DataFrame({
    "열 이름": df_raw.columns,
    "자료형(dtype)": df_raw.dtypes.astype(str).values,
    "빈 값(Null) 개수": df_raw.isna().sum().values,
    "고유값(Unique) 개수": df_raw.nunique().values
})
st.dataframe(overview_df, use_container_width=True, hide_index=True)

# ---------------------------------------------------------
# 4. [체크리스트 5] 데이터 전처리 기준 및 처리 전후 비교
# ---------------------------------------------------------
st.header("2. 데이터 전처리 기준 및 처리 전후 비교")
with st.expander("📌 우리 팀의 결측치·이상치 처리 기준 보기 (클릭)", expanded=True):
    st.markdown("""
    1. **결측치 제거**: `URL` 또는 `정답(Label)` 열이 비어 있거나(`NaN`, `null`) 공백만 있는 행 제거
    2. **중복 제거**: 완전히 동일한 중복 URL 제거
    3. **이상치 제거**: 도메인 구분자(`.`)가 없거나 길이가 5자 미만인 깨진 주소 문자열 제거
    4. **표기 통일**: URL 앞뒤 공백 제거 및 소문자 통일, 정답 라벨을 `정상(0)`과 `악성(1)` 두 범주로 통일
    """)

# 전처리 실행
df = df_raw[[url_col, label_col]].copy()
df.columns = ["url", "raw_label"]

before_rows = len(df)

# (1) 결측치 제거
df = df.dropna(subset=["url", "raw_label"])
df["url"] = df["url"].astype(str).str.strip()
df = df[df["url"] != ""]
after_na_rows = len(df)

# (2) 소문자 변환 및 중복 제거
df["url"] = df["url"].str.lower()
df = df.drop_duplicates(subset=["url"])
after_dup_rows = len(df)

# (3) 이상치 제거 (도메인 점(.) 미포함 또는 길이 5 미만)
df = df[df["url"].str.contains(r"\.", regex=True) & (df["url"].str.len() >= 5)]
after_rows = len(df)

# (4) 라벨 표기 통일 (정상 vs 악성)
def normalize_label(val):
    s = str(val).strip().lower()
    if s in ["0", "benign", "normal", "legitimate", "정상", "false"]:
        return "정상 URL"
    return "악성 URL"

df["구분"] = df["raw_label"].apply(normalize_label)

# 전후 비교 지표 출력
m1, m2, m3, m4 = st.columns(4)
m1.metric("전처리 전 행 수", f"{before_rows:,} 행")
m2.metric("결측치 제거 후", f"{after_na_rows:,} 행", f"-{before_rows - after_na_rows:,} 행")
m3.metric("중복·이상치 제거 후", f"{after_rows:,} 행", f"-{after_na_rows - after_rows:,} 행")
m4.metric("최종 데이터 보존율", f"{(after_rows / before_rows * 100):.1f} %" if before_rows > 0 else "0%")

st.divider()

# ---------------------------------------------------------
# 5. [체크리스트 2 & 3] 탐색적 데이터 분석 (EDA) 시각화
# ---------------------------------------------------------
st.header("3. 탐색적 데이터 분석 (EDA) — 정상 vs 악성 URL 특징 비교")

# 파생 변수 생성 (길이, 특수문자 개수)
df["url_length"] = df["url"].str.len()
df["dot_count"] = df["url"].str.count(r"\.")
df["hyphen_count"] = df["url"].str.count("-")
df["slash_count"] = df["url"].str.count("/")
df["query_count"] = df["url"].str.count(r"\?")

col_left, col_right = st.columns(2)

# [그래프 1] 정상 vs 악성 URL 데이터 개수 비교 (막대그래프)
with col_left:
    count_df = df["구분"].value_counts().reset_index()
    count_df.columns = ["URL 유형", "데이터 개수"]
    fig1 = px.bar(
        count_df,
        x="URL 유형",
        y="데이터 개수",
        color="URL 유형",
        text="데이터 개수",
        title="그래프 1. 정상 URL vs 악성 URL 데이터 분포",
        color_discrete_map={"정상 URL": "#2E86C1", "악성 URL": "#E74C3C"}
    )
    fig1.update_traces(textposition="outside")
    fig1.update_layout(xaxis_title="URL 유형 (정상 vs 악성)", yaxis_title="데이터 개수 (건)", showlegend=False)
    st.plotly_chart(fig1, use_container_width=True)

# [그래프 2] 정상 vs 악성 URL 길이 분포 비교 (상자그림)
with col_right:
    fig2 = px.box(
        df,
        x="구분",
        y="url_length",
        color="구분",
        title="그래프 2. URL 유형별 전체 글자 수(길이) 분포 비교",
        color_discrete_map={"정상 URL": "#2E86C1", "악성 URL": "#E74C3C"}
    )
    fig2.update_layout(xaxis_title="URL 유형 (정상 vs 악성)", yaxis_title="URL 전체 길이 (글자 수)", showlegend=False)
    st.plotly_chart(fig2, use_container_width=True)

# [그래프 3] 의심 특수문자 평균 개수 비교 (그룹 막대그래프)
special_df = df.groupby("구분")[["dot_count", "hyphen_count", "slash_count", "query_count"]].mean().reset_index()
special_melted = special_df.melt(id_vars="구분", var_name="특수문자 종류", value_name="평균 개수")
name_map = {
    "dot_count": "점(.) 개수",
    "hyphen_count": "하이픈(-) 개수",
    "slash_count": "슬래시(/) 개수",
    "query_count": "물음표(?) 개수"
}
special_melted["특수문자 종류"] = special_melted["특수문자 종류"].map(name_map)

fig3 = px.bar(
    special_melted,
    x="특수문자 종류",
    y="평균 개수",
    color="구분",
    barmode="group",
    text_auto=".2f",
    title="그래프 3. 정상 vs 악성 URL의 주요 특수문자 평균 등장 횟수 비교",
    color_discrete_map={"정상 URL": "#2E86C1", "악성 URL": "#E74C3C"}
)
fig3.update_layout(xaxis_title="URL 내 특수문자 종류", yaxis_title="URL당 평균 등장 횟수 (회)")
st.plotly_chart(fig3, use_container_width=True)

# ---------------------------------------------------------
# 6. [체크리스트 3 & 4] 그래프 근거 수치 요약 표
# ---------------------------------------------------------
st.header("4. 그래프로 찾아낸 근거 수치 요약")
summary_stats = df.groupby("구분").agg(
    데이터_수=("url", "count"),
    평균_URL_길이=("url_length", "mean"),
    중앙값_URL_길이=("url_length", "median"),
    최대_URL_길이=("url_length", "max"),
    평균_점_개수=("dot_count", "mean"),
    평균_슬래시_개수=("slash_count", "mean")
).round(2).reset_index()

st.dataframe(summary_stats, use_container_width=True, hide_index=True)

with st.expander("👀 전처리 완료된 데이터 미리보기 (상위 10행)"):
    st.dataframe(df[["url", "구분", "url_length", "dot_count", "slash_count"]].head(10), use_container_width=True)
