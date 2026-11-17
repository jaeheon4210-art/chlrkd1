import io
import json
import os
import zipfile
import pandas as pd
import plotly.express as px
import streamlit as st

# 1. 페이지 기본 설정 (사이드바 기본 펼침)
st.set_page_config(
    page_title="사이버보안 URL 데이터 탐색 대시보드",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.title("🛡️ 범용 생성형 AI는 정말 악성 URL과 정상 URL을 구별할 수 있을까?")

# ---------------------------------------------------------
# 2. 데이터 파싱 및 자동 탐색 함수 (JSON / CSV / ZIP 완벽 지원)
# ---------------------------------------------------------
def extract_records_from_json(obj):
    if isinstance(obj, list):
        if len(obj) > 0 and isinstance(obj[0], dict):
            return pd.json_normalize(obj)
        return pd.DataFrame({"value": obj})
    elif isinstance(obj, dict):
        # 리스트 형태의 핵심 데이터 키 우선 탐색
        best_list = []
        for k, v in obj.items():
            if isinstance(v, list) and len(v) > len(best_list):
                best_list = v
        if len(best_list) > 0:
            if isinstance(best_list[0], dict):
                return pd.json_normalize(best_list)
            return pd.DataFrame({"value": best_list})
        return pd.json_normalize(obj)
    return pd.DataFrame()

def read_bytes_to_df(filename, raw_bytes):
    fname = filename.lower()
    if fname.endswith(".csv"):
        for enc in ["utf-8", "utf-8-sig", "cp949", "euc-kr"]:
            try:
                return pd.read_csv(io.BytesIO(raw_bytes), encoding=enc)
            except Exception:
                continue
    elif fname.endswith(".json"):
        for enc in ["utf-8", "utf-8-sig", "cp949", "euc-kr"]:
            try:
                text = raw_bytes.decode(enc)
                parsed = json.loads(text)
                return extract_records_from_json(parsed)
            except Exception:
                continue
    elif fname.endswith(".zip"):
        dfs = []
        with zipfile.ZipFile(io.BytesIO(raw_bytes)) as zf:
            for inner_name in zf.namelist():
                if inner_name.lower().endswith((".json", ".csv")) and not inner_name.startswith("__MACOSX"):
                    sub_df = read_bytes_to_df(inner_name, zf.read(inner_name))
                    if sub_df is not None and not sub_df.empty:
                        dfs.append(sub_df)
        if dfs:
            return pd.concat(dfs, ignore_index=True)
    return None

def get_builtin_kisa_sample():
    # KISA 사이버보안 AI데이터셋 구조 기반 샘플 (결측치·중복·이상치 포함)
    records = [
        # 정상 URL (benign)
        {"url": "https://www.kisa.or.kr/401/form?postSeq=3120", "label": "benign"},
        {"url": "https://www.data.go.kr/data/15134424/fileData.do", "label": "benign"},
        {"url": "https://www.naver.com/", "label": "benign"},
        {"url": "https://www.kakao.com/main", "label": "benign"},
        {"url": "https://www.samsung.com/sec/semiconductors/", "label": "benign"},
        {"url": "https://www.skhynix.com/kor/index.do", "label": "benign"},
        {"url": "https://www.gov.kr/portal/main", "label": "benign"},
        {"url": "https://www.google.com/search?q=ai+semiconductor", "label": "benign"},
        {"url": "https://github.com/streamlit/streamlit", "label": "benign"},
        {"url": "https://www.moe.go.kr/main.do?s=moe", "label": "benign"},
        {"url": "https://www.scienceall.com/", "label": "benign"},
        {"url": "https://www.kisti.re.kr/", "label": "benign"},
        {"url": "https://www.etri.re.kr/kor/main/main.etri", "label": "benign"},
        {"url": "https://www.kaist.ac.kr/kr/", "label": "benign"},
        {"url": "https://www.snu.ac.kr/index.html", "label": "benign"},
        {"url": "https://www.boho.or.kr/kr/main.do", "label": "benign"},
        {"url": "https://www.krcert.or.kr/", "label": "benign"},
        {"url": "https://www.nts.go.kr/nts/main.do", "label": "benign"},
        {"url": "https://www.police.go.kr/index.do", "label": "benign"},
        {"url": "https://www.fss.or.kr/fss/main/main.do", "label": "benign"},
        {"url": "https://www.bok.or.kr/portal/main/main.do", "label": "benign"},
        {"url": "https://www.coursera.org/learn/machine-learning", "label": "benign"},
        {"url": "https://docs.python.org/3/library/json.html", "label": "benign"},
        {"url": "https://pandas.pydata.org/docs/user_guide/index.html", "label": "benign"},
        {"url": "https://www.wikipedia.org/wiki/Artificial_intelligence", "label": "benign"},
        {"url": "https://www.youtube.com/watch?v=AQMH1T4Kjnw", "label": "benign"},
        {"url": "https://www.coupang.com/np/categories/194176", "label": "benign"},
        {"url": "https://www.kyobobook.co.kr/", "label": "benign"},
        {"url": "https://www.weather.go.kr/w/index.do", "label": "benign"},
        {"url": "https://www.korail.com/main", "label": "benign"},
        # 악성 URL (malicious / phishing)
        {"url": "http://kisa-security-verify-login.com/auth/update.php?id=99281", "label": "malicious"},
        {"url": "http://naver-account-check-2026.xyz/login/confirm?user=test", "label": "malicious"},
        {"url": "http://gov-kr-tax-refund-notice.info/apply/index.html?token=8812", "label": "malicious"},
        {"url": "http://192.168.104.22/malware/payload_dropper.exe", "label": "malicious"},
        {"url": "http://parcel-delivery-tracking-kr.top/sms/view.php?code=7741", "label": "malicious"},
        {"url": "http://kakao-cert-renewal-alert.club/verify/step1?session=ab12cd", "label": "malicious"},
        {"url": "http://bank-security-card-update.site/kr/login.jsp?err=1", "label": "malicious"},
        {"url": "http://free-gift-event-claim-now.online/win/prize?ref=sms01", "label": "malicious"},
        {"url": "http://microsoft-onedrive-doc-share.vip/view/invoice_2026.pdf.exe", "label": "malicious"},
        {"url": "http://police-summons-notice-check.net/case/detail.php?no=40291", "label": "malicious"},
        {"url": "http://samsung-pay-reward-point.shop/claim/auth?uid=5510", "label": "malicious"},
        {"url": "http://apple-id-locked-unlock-now.icu/signin/verify?lang=ko", "label": "malicious"},
        {"url": "http://health-insurance-refund-2026.buzz/nhis/check.php?p=1", "label": "malicious"},
        {"url": "http://203.0.113.88:8080/botnet/gate.php?cmd=init", "label": "malicious"},
        {"url": "http://urgent-account-suspension-warning.work/portal/reset?id=33", "label": "malicious"},
        {"url": "http://cj-logistics-address-error.click/re-delivery/form.html", "label": "malicious"},
        {"url": "http://google-drive-shared-file-viewer.link/download/setup.scr", "label": "malicious"},
        {"url": "http://nts-hometax-overdue-notice.monster/tax/pay.php?code=910", "label": "malicious"},
        {"url": "http://mobile-carrier-point-expire.today/kt-skt/redeem?m=1", "label": "malicious"},
        {"url": "http://crypto-wallet-airdrop-bonus.pro/connect/metamask?v=2", "label": "malicious"},
        {"url": "http://fss-financial-supervisory-alert.xyz/safe/install_app.apk", "label": "malicious"},
        {"url": "http://coupang-order-cancel-refund.top/cs/verify.php?ord=77821", "label": "malicious"},
        {"url": "http://instagram-copyright-violation-appeal.info/help/confirm", "label": "malicious"},
        {"url": "http://zoom-meeting-client-update-required.site/bin/ZoomInstaller.exe", "label": "malicious"},
        {"url": "http://198.51.100.45/c2/beacon.php?host=win10-pc", "label": "malicious"},
        {"url": "http://netflix-payment-declined-update.club/billing/card?retry=true", "label": "malicious"},
        {"url": "http://kr-post-office-customs-fee.online/pay/tracking?id=KR99201", "label": "malicious"},
        {"url": "http://discord-nitro-free-3months-gift.shop/claim/login", "label": "malicious"},
        {"url": "http://bank-otp-reissue-center.vip/security/otp.php?step=2", "label": "malicious"},
        {"url": "http://university-scholarship-apply-2026.work/student/login.php", "label": "malicious"},
        # 결측치, 중복, 이상치 테스트용 데이터 (전처리 전후 비교 확인용)
        {"url": None, "label": "malicious"},
        {"url": "https://www.naver.com/", "label": "benign"},
        {"url": "   ", "label": "benign"},
        {"url": "http://naver-account-check-2026.xyz/login/confirm?user=test", "label": "malicious"},
        {"url": "invalid_url_no_dot", "label": "malicious"},
        {"url": "abc", "label": None},
    ]
    return pd.DataFrame(records)

def find_repo_data_file():
    ignore_dirs = {".git", "__pycache__", "venv", ".venv", "node_modules", ".streamlit"}
    for root, dirs, files in os.walk("."):
        dirs[:] = [d for d in dirs if d not in ignore_dirs]
        for f in files:
            if f.lower().endswith((".json", ".csv", ".zip")) and f.lower() not in ["package.json", "tsconfig.json"]:
                full_path = os.path.join(root, f)
                with open(full_path, "rb") as fp:
                    df = read_bytes_to_df(f, fp.read())
                if df is not None and not df.empty:
                    return df, full_path
    return None, None

# 메인 화면 상단 업로드 영역 (사이드바가 닫혀 있어도 바로 보이도록 배치)
with st.expander("📂 데이터 파일 변경 / 직접 업로드하기 (클릭)", expanded=False):
    uploaded = st.file_uploader(
        "공공데이터포털(KISA)에서 내려받은 JSON, CSV 또는 ZIP 파일을 올려주세요.",
        type=["json", "csv", "zip"]
    )

df_raw = None
data_source_label = ""

if uploaded is not None:
    df_raw = read_bytes_to_df(uploaded.name, uploaded.read())
    data_source_label = f"업로드된 파일 (`{uploaded.name}`)"
else:
    repo_df, repo_path = find_repo_data_file()
    if repo_df is not None:
        df_raw = repo_df
        data_source_label = f"저장소 파일 (`{repo_path}`)"
    else:
        df_raw = get_builtin_kisa_sample()
        data_source_label = "내장 KISA 사이버보안 AI데이터셋 샘플 (자동 실행 모드)"

st.info(f"✅ 현재 분석 중인 데이터: **{data_source_label}**")

# 사이드바 열 선택 옵션
st.sidebar.header("⚙️ 분석 열 설정")
cols = list(df_raw.columns)
default_url_idx = next((i for i, c in enumerate(cols) if any(k in c.lower() for k in ["url", "uri", "domain", "link", "주소", "value"])), 0)
default_lbl_idx = next((i for i, c in enumerate(cols) if any(k in c.lower() for k in ["label", "type", "class", "mal", "악성", "유형", "구분"])), min(1, len(cols)-1))

url_col = st.sidebar.selectbox("URL(웹 주소) 열", cols, index=default_url_idx)
label_col = st.sidebar.selectbox("정답(정상/악성) 열", cols, index=default_lbl_idx) if len(cols) > 1 else None

st.divider()

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
with st.expander("📌 우리 팀의 결측치·이상치 처리 기준 보기", expanded=True):
    st.markdown("""
    1. **결측치 제거**: `URL` 또는 `정답(Label)` 열이 비어 있거나(`NaN`, `null`) 공백만 있는 행 제거
    2. **중복 제거**: 완전히 동일한 중복 URL 제거
    3. **이상치 제거**: 도메인 구분자(`.`)가 없거나 길이가 5자 미만인 깨진 문자열 제거
    4. **표기 통일**: URL 앞뒤 공백 제거 및 소문자 통일, 정답 라벨을 `정상 URL`과 `악성 URL` 두 범주로 통일
    """)

if label_col is not None and label_col != url_col:
    df = df_raw[[url_col, label_col]].copy()
    df.columns = ["url", "raw_label"]
else:
    df = df_raw[[url_col]].copy()
    df.columns = ["url"]
    df["raw_label"] = "malicious"

before_rows = len(df)

# (1) 결측치 제거
df = df.dropna(subset=["url", "raw_label"])
df["url"] = df["url"].astype(str).str.strip()
df = df[(df["url"] != "") & (df["url"].str.lower() != "none") & (df["url"].str.lower() != "nan")]
after_na_rows = len(df)

# (2) 소문자 변환 및 중복 제거
df["url"] = df["url"].str.lower()
df = df.drop_duplicates(subset=["url"])

# (3) 이상치 제거 (도메인 점(.) 미포함 또는 길이 5 미만)
df = df[df["url"].str.contains(r"\.", regex=True) & (df["url"].str.len() >= 5)]
after_rows = len(df)

# (4) 라벨 표기 통일
def normalize_label(val):
    s = str(val).strip().lower()
    if s in ["0", "benign", "normal", "legitimate", "정상", "false", "safe"]:
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

df["url_length"] = df["url"].str.len()
df["dot_count"] = df["url"].str.count(r"\.")
df["hyphen_count"] = df["url"].str.count("-")
df["slash_count"] = df["url"].str.count("/")
df["query_count"] = df["url"].str.count(r"\?")
df["is_https"] = df["url"].str.startswith("https://").map({True: "HTTPS (보안 프로토콜)", False: "HTTP / 기타"})

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
