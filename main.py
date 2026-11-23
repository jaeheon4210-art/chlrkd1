import io
import json
import os
import zipfile
import altair as alt
import pandas as pd
import streamlit as st

alt.data_transformers.disable_max_rows()

# 1. 페이지 기본 설정
st.set_page_config(
    page_title="사이버보안 URL 데이터 분석 대시보드",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# ---------------------------------------------------------
# 2. 데이터 로드 함수 (CSV / JSON / ZIP 및 내장 샘플 지원)
# ---------------------------------------------------------
def read_bytes_to_df(filename, raw_bytes):
    fname = filename.lower()
    if fname.endswith(".csv"):
        for enc in ["utf-8", "utf-8-sig", "cp949", "euc-kr"]:
            try:
                return pd.read_csv(io.BytesIO(raw_bytes), encoding=enc)
            except Exception:
                continue
    elif fname.endswith(".json"):
        for enc in ["utf-8", "utf-8-sig", "cp949"]:
            try:
                parsed = json.loads(raw_bytes.decode(enc))
                if isinstance(parsed, list):
                    return pd.json_normalize(parsed)
                for v in parsed.values():
                    if isinstance(v, list) and len(v) > 0:
                        return pd.json_normalize(v)
                return pd.json_normalize(parsed)
            except Exception:
                continue
    elif fname.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(raw_bytes)) as zf:
            for inner in zf.namelist():
                if inner.lower().endswith((".csv", ".json")) and not inner.startswith("__MACOSX"):
                    df = read_bytes_to_df(inner, zf.read(inner))
                    if df is not None and not df.empty:
                        return df
    return None

def find_repo_data_file():
    ignore_dirs = {".git", "__pycache__", "venv", ".venv", ".streamlit"}
    for root, dirs, files in os.walk("."):
        dirs[:] = [d for d in dirs if d not in ignore_dirs]
        for f in files:
            if f.lower().endswith((".csv", ".json", ".zip")) and f.lower() not in ["package.json", "tsconfig.json"]:
                full_path = os.path.join(root, f)
                with open(full_path, "rb") as fp:
                    df = read_bytes_to_df(f, fp.read())
                if df is not None and not df.empty:
                    return df, full_path
    return None, None

def get_builtin_sample():
    records = [
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
        {"url": "https://www.coupang.com/np/categories/194176", "label": "benign"},
        {"url": "https://www.kyobobook.co.kr/", "label": "benign"},
        {"url": "https://www.weather.go.kr/w/index.do", "label": "benign"},
        {"url": "https://www.korail.com/main", "label": "benign"},
        {"url": "https://www.ebs.co.kr/main", "label": "benign"},
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
        {"url": None, "label": "malicious"},
        {"url": "https://www.naver.com/", "label": "benign"},
        {"url": "   ", "label": "benign"},
        {"url": "invalid_url_no_dot", "label": "malicious"},
        {"url": "abc", "label": None},
    ]
    return pd.DataFrame(records)

# ---------------------------------------------------------
# 3. 사이드바 (파일 업로드 및 색상 테마 설정)
# ---------------------------------------------------------
with st.sidebar:
    st.header("🎨 화면 및 데이터 설정")
    theme_choice = st.selectbox(
        "그래프 색상 테마",
        ["사이버 블루 & 레드", "에메랄드 틸 & 오렌지", "딥 인디고 & 코랄"]
    )
    palette_map = {
        "사이버 블루 & 레드": ["#1E88E5", "#E53935"],
        "에메랄드 틸 & 오렌지": ["#00897B", "#F4511E"],
        "딥 인디고 & 코랄": ["#3949AB", "#D81B60"]
    }
    normal_color, mal_color = palette_map[theme_choice]

    st.divider()
    uploaded = st.file_uploader("데이터 파일 변경 (CSV / JSON / ZIP)", type=["csv", "json", "zip"])

if uploaded is not None:
    df_raw = read_bytes_to_df(uploaded.name, uploaded.read())
    source_label = uploaded.name
else:
    df_raw, repo_path = find_repo_data_file()
    source_label = os.path.basename(repo_path) if df_raw is not None else "KISA 사이버보안 AI데이터셋 샘플"

if df_raw is None or df_raw.empty:
    df_raw = get_builtin_sample()
    source_label = "KISA 사이버보안 AI데이터셋 샘플"

# ---------------------------------------------------------
# 4. 자동 열 매핑 및 전처리 실행
# ---------------------------------------------------------
cols = list(df_raw.columns)
url_col = next((c for c in cols if c.lower() in ["url", "uri", "domain", "홈페이지주소"]), cols[0])
label_col = next((c for c in cols if c.lower() in ["label", "status", "type", "class"]), cols[min(1, len(cols)-1)])
is_phiusiil = "URLSimilarityIndex" in df_raw.columns or "FILENAME" in df_raw.columns

df = df_raw[[url_col, label_col]].copy()
df.columns = ["url", "raw_label"]
before_rows = len(df)

df = df.dropna(subset=["url", "raw_label"])
df["url"] = df["url"].astype(str).str.strip()
df = df[(df["url"] != "") & (df["url"].str.lower() != "nan") & (df["url"].str.lower() != "none")]
after_na_rows = len(df)

df["url"] = df["url"].str.lower()
df = df.drop_duplicates(subset=["url"])
df = df[df["url"].str.contains(r"\.", regex=True) & (df["url"].str.len() >= 5)]
after_rows = len(df)

def map_label(val):
    s = str(val).strip().lower()
    if s in ["1", "1.0"]:
        return "정상 URL" if is_phiusiil else "악성 URL"
    if s in ["0", "0.0"]:
        return "악성 URL" if is_phiusiil else "정상 URL"
    if s in ["benign", "legitimate", "normal", "정상", "safe"]:
        return "정상 URL"
    return "악성 URL"

df["구분"] = df["raw_label"].apply(map_label)
df["url_length"] = df["url"].str.len()
df["dot_count"] = df["url"].str.count(r"\.")
df["hyphen_count"] = df["url"].str.count("-")
df["slash_count"] = df["url"].str.count("/")
df["query_count"] = df["url"].str.count(r"\?")
df["equal_count"] = df["url"].str.count("=")
df["special_total"] = df["dot_count"] + df["hyphen_count"] + df["slash_count"] + df["query_count"] + df["equal_count"]
df["is_https"] = df["url"].str.startswith("https://").map({True: "HTTPS 사용", False: "HTTP / 기타"})

# ---------------------------------------------------------
# 5. 상단 타이틀 및 핵심 요약
# ---------------------------------------------------------
st.title("🛡️ 범용 생성형 AI는 정말 악성 URL과 정상 URL을 구별할 수 있을까?")
st.caption(f"분석 데이터: **{source_label}** | 3·4차시 데이터 전처리 및 탐색적 데이터 분석(EDA)")

normal_df = df[df["구분"] == "정상 URL"]
mal_df = df[df["구분"] == "악성 URL"]
normal_avg_len = normal_df["url_length"].mean() if len(normal_df) > 0 else 0
mal_avg_len = mal_df["url_length"].mean() if len(mal_df) > 0 else 0

k1, k2, k3, k4 = st.columns(4)
k1.metric("정제 완료 데이터", f"{after_rows:,} 건", f"원본 대비 {(after_rows/before_rows*100):.1f}% 보존")
k2.metric("정상 : 악성 건수", f"{len(normal_df):,} : {len(mal_df):,}")
k3.metric("정상 URL 평균 길이", f"{normal_avg_len:.1f} 자")
k4.metric("악성 URL 평균 길이", f"{mal_avg_len:.1f} 자", f"{(mal_avg_len - normal_avg_len):+.1f} 자")

st.write("")

# ---------------------------------------------------------
# 6. 3단 탭 구성
# ---------------------------------------------------------
tab1, tab2, tab3 = st.tabs([
    "📈 탐색적 데이터 분석 (그래프 선택)",
    "🧹 데이터 전처리 비교",
    "📋 원본 데이터 개요"
])

color_scale = alt.Scale(domain=["정상 URL", "악성 URL"], range=[normal_color, mal_color])

# [탭 1] 그래프 1개 + 선택지 + 근거 수치 자동 출력
with tab1:
    chart_option = st.radio(
        "📌 보고 싶은 그래프를 선택하세요:",
        [
            "1. 정상 vs 악성 URL 구성 비율 (도넛 차트)",
            "2. URL 전체 길이 분포 비교 (히스토그램)",
            "3. 의심 특수문자 평균 빈도 비교 (가로 막대그래프)",
            "4. HTTPS 보안 프로토콜 사용 비율 (누적 막대그래프)",
            "5. URL 길이와 특수문자 개수의 관계 (산점도)"
        ],
        horizontal=True
    )

    st.divider()

    if chart_option.startswith("1."):
        count_df = df["구분"].value_counts().reset_index()
        count_df.columns = ["URL 유형", "데이터 개수"]
        count_df["비율"] = (count_df["데이터 개수"] / count_df["데이터 개수"].sum() * 100).round(1)

        chart = alt.Chart(count_df).mark_arc(innerRadius=85, outerRadius=160).encode(
            theta=alt.Theta("데이터 개수:Q", title="데이터 개수 (건)"),
            color=alt.Color("URL 유형:N", scale=color_scale, legend=alt.Legend(title="URL 유형 (정상 vs 악성)")),
            tooltip=["URL 유형", alt.Tooltip("데이터 개수:Q", format=","), alt.Tooltip("비율:Q", format=".1f", title="비율(%)")]
        ).properties(title="정상 URL vs 악성 URL 데이터 구성 비율", height=420)
        st.altair_chart(chart, use_container_width=True)

        n_pct = (len(normal_df) / len(df) * 100) if len(df) > 0 else 0
        m_pct = (len(mal_df) / len(df) * 100) if len(df) > 0 else 0
        st.info(f"💡 **근거 수치 요약**: 전처리 후 총 **{len(df):,}건** 중 정상 URL은 **{len(normal_df):,}건({n_pct:.1f}%)**, 악성 URL은 **{len(mal_df):,}건({m_pct:.1f}%)**입니다.")

    elif chart_option.startswith("2."):
        plot_df = df.sample(n=10000, random_state=42) if len(df) > 10000 else df
        chart = alt.Chart(plot_df).mark_bar(opacity=0.65).encode(
            x=alt.X("url_length:Q", bin=alt.Bin(maxbins=25), title="URL 전체 길이 (글자 수)"),
            y=alt
