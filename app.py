
# -*- coding: utf-8 -*-
"""
==========================================
복지시설 투약 관리 (단일 비밀번호 게이트 + 삭제 기능 + 전체 선택/유지) — app.py
==========================================

[설정 가이드 - .streamlit/secrets.toml]
---------------------------------------
[app]
password_hash = "pbkdf2_sha256$260000$SALT_BASE64$DERIVED_KEY_BASE64"
max_attempts = 5
lock_minutes = 10

- password_hash 는 평문이 아니라 "해시 문자열"입니다.
- 해시는 이 앱의 "🔧 관리자 도구: 비밀번호 해시 생성기"에서 생성 가능.
- 절대 평문 비밀번호를 저장/배포하지 마세요.

[주의]
- 이 앱은 "단일 비밀번호"를 공유하는 간편 보안 방식입니다.
  사용자별 접근제어/감사 기능은 제공하지 않으므로,
  비밀번호 유출/공유에 취약할 수 있습니다.
- 데이터(CSV)는 앱과 동일 폴더에 저장됩니다.
  Streamlit Cloud 등 무상 호스팅에서는 컨테이너 교체 시
  파일이 초기화되거나 내구성이 약할 수 있으니 유의하세요.
"""

import os
import time
import base64
import hashlib
import hmac
import uuid
from datetime import date, timedelta

import pandas as pd
import streamlit as st

# -------------------------------
# 기본 설정
# -------------------------------
st.set_page_config(page_title="복지시설 투약 관리", layout="wide")
st.title("💊 생활인 투약 관리 시스템 (비밀번호 게이트 포함 / 무료 배포용)")

# (선택) 비밀번호 입력칸 추가 스타일: 너무 넓어 보일 때 최대 폭 제한
st.markdown("""
<style>
/* password input 필드 최대 폭(픽셀) - 필요 없으면 이 블록을 지워도 됩니다 */
section[data-testid="stTextInput"] input[type="password"] {
  max-width: 480px;  /* 360~480px 정도가 깔끔합니다 */
}
</style>
""", unsafe_allow_html=True)

DB_FILE = "medication_data.csv"

# -------------------------------
# (A) 단일 비밀번호 게이트 (공유 비밀번호)
# -------------------------------
def verify_password(plain: str, stored: str) -> bool:
    """
    PBKDF2 해시 검증
    형식: pbkdf2_sha256$<iterations>$<salt_b64>$<dk_b64>
    """
    try:
        algo, iters, salt_b64, dk_b64 = stored.split("$")
        assert algo == "pbkdf2_sha256"
        iters = int(iters)
        salt = base64.b64decode(salt_b64)
        dk_true = base64.b64decode(dk_b64)
        dk_test = hashlib.pbkdf2_hmac("sha256", plain.encode("utf-8"), salt, iters)
        return hmac.compare_digest(dk_true, dk_test)
    except Exception:
        return False

def make_hash(plain: str, iterations: int = 260_000) -> str:
    """PBKDF2 해시 생성기 (관리자 도구 용)"""
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", plain.encode("utf-8"), salt, iterations)
    return f"pbkdf2_sha256${iterations}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"

# --- secrets 안전 로딩 ---
def _load_app_cfg():
    try:
        _s = st.secrets  # 없으면 여기서 예외 발생
        return dict(_s.get("app", {}))  # 섹션 없으면 {}
    except Exception:
        return {}

APP_CFG = _load_app_cfg()
PASSWORD_HASH = (APP_CFG.get("password_hash") or "").strip()
MAX_ATTEMPTS = int(APP_CFG.get("max_attempts", 5))
LOCK_MINUTES = int(APP_CFG.get("lock_minutes", 10))

# --- 상태값 ---
if "auth_ok" not in st.session_state:
    st.session_state.auth_ok = False
if "fail_count" not in st.session_state:
    st.session_state.fail_count = 0
if "locked_until" not in st.session_state:
    st.session_state.locked_until = 0.0

# --- 관리자 도구(해시 생성기): '정말 필요할 때'만 보여주기 ---
def render_admin_tools():
    if PASSWORD_HASH:
        return
    with st.expander("🔧 관리자 도구: 비밀번호 해시 생성기 (초기 설정용)", expanded=True):
        st.caption(
            "① 평문 비밀번호를 입력하면 해시를 생성합니다. "
            "② 생성된 문자열을 `.streamlit/secrets.toml`의 [app].password_hash 에 저장하세요."
        )
        col1, col2 = st.columns([2, 1])
        with col1:
            plain = st.text_input("평문 비밀번호 입력(표시됨)", value="", type="default")
        with col2:
            iters = st.number_input("iterations", min_value=100_000, value=260_000, step=10_000)
        if st.button("해시 생성하기"):
            if plain:
                def _make_hash(p: str, iterations: int = 260_000) -> str:
                    salt = os.urandom(16)
                    dk = hashlib.pbkdf2_hmac("sha256", p.encode("utf-8"), salt, iterations)
                    import base64 as b64
                    return f"pbkdf2_sha256${iterations}${b64.b64encode(salt).decode()}${b64.b64encode(dk).decode()}"
                hashed = _make_hash(plain, int(iters))
                st.code(hashed, language="text")
                st.success("위 문자열을 secrets.toml에 저장한 뒤, 앱을 Rerun 하세요.")
            else:
                st.warning("평문 비밀번호를 입력해 주세요.")

# --- 로그인 폼 (중앙 정렬 + 가로폭 1/3 + Enter 제출) ---
def login_form(now_ts: float, align: str = "center", width_fraction: float = 1/3):
    """
    비밀번호 입력 폼
    - align: "center" 또는 "left"
    - width_fraction: 입력 영역 가로폭(0~1), 기본 1/3
    - Enter 키로도 제출 가능 (st.form + form_submit_button)
    """
    st.subheader("🔐 접근 비밀번호를 입력하세요.")

    # 컬럼으로 영역 폭/정렬 제어
    width_fraction = max(0.2, min(width_fraction, 1.0))
    if align == "left":
        left_col, right_sp = st.columns([width_fraction, 1 - width_fraction])
        target_col = left_col
    else:
        side = (1 - width_fraction) / 2
        _, target_col, _ = st.columns([side, width_fraction, side])

    with target_col:
        # ✅ 폼을 쓰면 텍스트 입력 후 Enter 키로도 제출됩니다.
        with st.form("login_form", clear_on_submit=False):
            pwd = st.text_input("비밀번호", type="password", label_visibility="visible")
            c1, c2 = st.columns([1, 1])
            with c1:
                submit = st.form_submit_button("입장하기", use_container_width=True)
            with c2:
                st.caption(f"※ 연속 실패 {MAX_ATTEMPTS}회 시 {LOCK_MINUTES}분 잠금")

        if submit:
            if not PASSWORD_HASH:
                st.error("서버 비밀번호가 아직 설정되지 않았습니다. 관리자에게 문의하세요.")
                return
            try:
                algo, iters, salt_b64, dk_b64 = PASSWORD_HASH.split("$")
                assert algo == "pbkdf2_sha256"
                iters = int(iters)
                salt = base64.b64decode(salt_b64)
                dk_true = base64.b64decode(dk_b64)
                dk_test = hashlib.pbkdf2_hmac("sha256", pwd.encode("utf-8"), salt, iters)
                ok = hmac.compare_digest(dk_true, dk_test)
            except Exception:
                ok = False

            if ok:
                st.session_state.auth_ok = True
                st.session_state.fail_count = 0
                st.session_state.locked_until = 0.0
                st.success("접속 성공")
            else:
                st.session_state.fail_count += 1
                if st.session_state.fail_count >= MAX_ATTEMPTS:
                    st.session_state.locked_until = now_ts + (LOCK_MINUTES * 60)
                    st.warning(f"연속 {MAX_ATTEMPTS}회 실패로 {LOCK_MINUTES}분 잠금되었습니다.")
                else:
                    remain = MAX_ATTEMPTS - st.session_state.fail_count
                    st.error(f"비밀번호가 올바르지 않습니다. (남은 시도: {remain})")

# --- 게이트: '잠금' 또는 '미인증'일 때만 폼/도구 노출 ---
def render_gate_and_stop_if_not_authenticated():
    now_ts = time.time()
    # 잠금 상태
    if st.session_state.locked_until and now_ts < st.session_state.locked_until:
        left = int((st.session_state.locked_until - now_ts) // 60) + 1
        st.error(f"보안 잠금 중입니다. {left}분 후 다시 시도하세요.")
        render_admin_tools()
        st.stop()

    # 아직 로그인 안 됐으면 로그인 폼 (요청: 중앙/1/3 폭, Enter 제출 가능)
    if not st.session_state.auth_ok:
        login_form(now_ts, align="center", width_fraction=1/3)
        # 로그인 전이고 해시가 없다면 도구 노출
        render_admin_tools()
        if not st.session_state.auth_ok:
            st.stop()

# 실제 호출 (여기서 인증 통과 못하면 이후 UI 중단)
render_gate_and_stop_if_not_authenticated()

# 상단 보조 UI (로그아웃/안내)
with st.sidebar:
    if st.button("로그아웃"):
        st.session_state.auth_ok = False
        st.session_state.fail_count = 0
        st.session_state.locked_until = 0.0
        st.rerun()
    st.caption("보안을 위해 비밀번호는 주기적으로 교체하세요.")

# -------------------------------
# (B) 투약 관리 본 기능 (삭제 기능 포함)
# -------------------------------

def generate_id() -> str:
    """레코드 고유 ID"""
    return uuid.uuid4().hex

# 복용시간대 옵션
TIME_OPTIONS = [
    "아침약", "점심약", "저녁약", "아침 식전약", "저녁 식전약", "취침전약"
]
TIME_ORDER_MAP = {
    "아침 식전약": 0,
    "아침약": 1,
    "점심약": 2,
    "저녁 식전약": 3,
    "저녁약": 4,
    "취침전약": 5,
}

# '기록ID' 추가: 삭제/수정 식별자
REQUIRED_COLS = [
    "기록ID",  # 고유 식별자
    "이름", "병원명", "약품명", "처방일", "복용일수",
    "종료예정일", "비고", "남은약", "복용시간대"
]

def ensure_schema(df: pd.DataFrame) -> pd.DataFrame:
    if df is None or df.empty:
        df = pd.DataFrame(columns=REQUIRED_COLS)

    # 누락 컬럼 채움
    for col in REQUIRED_COLS:
        if col not in df.columns:
            if col == "기록ID":
                df[col] = ""
            elif col in ["복용일수", "남은약"]:
                df[col] = 0
            elif col in ["처방일", "종료예정일"]:
                df[col] = pd.NaT
            else:
                df[col] = ""

    # 타입 강제
    df["처방일"] = pd.to_datetime(df["처방일"], errors="coerce")
    df["종료예정일"] = pd.to_datetime(df["종료예정일"], errors="coerce")
    df["복용일수"] = pd.to_numeric(df["복용일수"], errors="coerce").fillna(0).astype(int)
    df["남은약"] = pd.to_numeric(df["남은약"], errors="coerce").fillna(0).astype(int)
    for col in ["기록ID", "이름", "병원명", "약품명", "비고", "복용시간대"]:
        df[col] = df[col].fillna("").astype(str)

    # 기록ID가 비어있는 행에 새 ID 부여
    mask_no_id = (df["기록ID"].str.len() == 0)
    if mask_no_id.any():
        df.loc[mask_no_id, "기록ID"] = [generate_id() for _ in range(mask_no_id.sum())]

    # 필수 날짜 결측 제거(입력 실수 방지)
    df = df.dropna(subset=["처방일", "종료예정일"])

    # 컬럼 순서 통일
    df = df[REQUIRED_COLS]
    return df

def load_data() -> pd.DataFrame:
    if os.path.exists(DB_FILE):
        try:
            df = pd.read_csv(DB_FILE, encoding="utf-8-sig")
            df = ensure_schema(df)
            return df
        except Exception as e:
            st.error(f"데이터 로드 중 오류 발생: {e}")
            return ensure_schema(pd.DataFrame(columns=REQUIRED_COLS))
    else:
        return ensure_schema(pd.DataFrame(columns=REQUIRED_COLS))

def save_data(df: pd.DataFrame):
    try:
        df_to_save = ensure_schema(df.copy())
        df_to_save.to_csv(DB_FILE, index=False, encoding="utf-8-sig")
    except Exception as e:
        st.error(f"데이터 저장 중 오류 발생: {e}")

# 세션 상태 초기화
if "data" not in st.session_state:
    st.session_state.data = load_data()
if "last_status" not in st.session_state:
    st.session_state.last_status = ""
if "search_text" not in st.session_state:
    st.session_state.search_text = ""
if "search_select" not in st.session_state:
    st.session_state.search_select = ""
if "undo_stack" not in st.session_state:
    st.session_state.undo_stack = []  # 삭제 전 백업용 (DataFrame deep copy)
# ✅ 선택 상태를 세션에 유지 (중요!)
if "delete_selected_ids" not in st.session_state:
    st.session_state.delete_selected_ids = []  # ['기록ID', ...]

# 사이드바: 신규 등록 + 검색
with st.sidebar:
    st.header("신규 투약 등록/업데이트")
    with st.form("register_form", clear_on_submit=True):
        input_name = st.text_input("생활인 성명", value="")
        input_hospital = st.text_input("병원/진료과", value="")
        input_med_name = st.text_input("약품명", value="")
        input_time_slot = st.selectbox("복용 시간대", options=TIME_OPTIONS, index=0)
        input_start_date = st.date_input("처방일", value=date.today())
        input_days = st.number_input("복용 일수", min_value=1, value=30)
        input_memo = st.text_area("비고/특이사항", value="")
        input_left_amount = st.number_input("남은 약 수량", min_value=0, value=0)
        submitted = st.form_submit_button("등록하기")

    if submitted:
        name = input_name.strip()
        hospital = input_hospital.strip()
        med_name = input_med_name.strip()
        time_slot = input_time_slot.strip() if input_time_slot else ""

        if not (name and hospital and med_name and time_slot):
            st.warning("모든 필수 정보를 입력해 주세요. (성명/병원/약품명/복용 시간대)")
        else:
            start_ts = pd.to_datetime(input_start_date)
            end_ts = start_ts + timedelta(days=int(input_days))
            new_row = pd.DataFrame([{
                "기록ID": generate_id(),
                "이름": name,
                "병원명": hospital,
                "약품명": med_name,
                "복용시간대": time_slot,
                "처방일": start_ts,
                "복용일수": int(input_days),
                "종료예정일": end_ts,
                "비고": input_memo.strip(),
                "남은약": int(input_left_amount),
            }])
            st.session_state.data = ensure_schema(pd.concat([st.session_state.data, new_row], ignore_index=True))
            save_data(st.session_state.data)
            st.session_state.last_status = f"✅ '{name}'님의 투약 정보가 성공적으로 저장되었습니다!"
            st.success(st.session_state.last_status)

    st.markdown("---")
    st.header("대상자 검색")
    names_list = sorted([n for n in st.session_state.data["이름"].dropna().unique() if n != ""])

    st.session_state.search_text = st.text_input(
        "이름(부분검색 가능)", value=st.session_state.search_text, placeholder="예: 홍길동"
    )
    st.session_state.search_select = st.selectbox(
        "이름(목록에서 선택)",
        options=[""] + names_list,
        index=([""] + names_list).index(st.session_state.search_select) if st.session_state.search_select in ([""] + names_list) else 0
    )

    col_a, col_b = st.columns(2)
    with col_a:
        apply_search = st.button("검색 적용")
    with col_b:
        clear_search = st.button("검색 해제(전체 보기)")

    if clear_search:
        st.session_state.search_text = ""
        st.session_state.search_select = ""
        # 검색 해제 시 선택 상태도 초기화(선택사항)
        st.session_state.delete_selected_ids = []

# 메인 대시보드
st.subheader("대상자 투약 현황 대시보드")

df_display = ensure_schema(st.session_state.data.copy())

if not df_display.empty:
    today_ts = pd.to_datetime(date.today())
    df_display["남은일수"] = (df_display["종료예정일"] - today_ts).dt.days

filtered_df = df_display.copy()

selected_name = st.session_state.search_select.strip() if st.session_state.search_select else ""
typed_query = st.session_state.search_text.strip()

if apply_search or selected_name or typed_query:
    if selected_name:
        filtered_df = filtered_df[filtered_df["이름"] == selected_name]
    elif typed_query:
        mask = filtered_df["이름"].str.contains(typed_query, case=False, na=False)
        filtered_df = filtered_df[mask]

# 개인 요약(단일 대상자일 때)
unique_names = filtered_df["이름"].dropna().unique().tolist() if not filtered_df.empty else []
if len(unique_names) == 1:
    person = unique_names[0]
    st.markdown(f"### 👤 '{person}' 개인 요약")
    person_df = filtered_df.copy()
    person_df["처방일(표시)"] = person_df["처방일"].dt.strftime("%Y-%m-%d")
    person_df["종료예정일(표시)"] = person_df["종료예정일"].dt.strftime("%Y-%m-%d")
    person_df["시간순서"] = person_df["복용시간대"].map(TIME_ORDER_MAP).fillna(999).astype(int)

    hospitals = person_df["병원명"].dropna().unique().tolist()
    hospitals = sorted([h for h in hospitals if h != ""])

    if hospitals:
        for h in hospitals:
            sub = person_df[person_df["병원명"] == h].copy()
            sub = sub.sort_values(["종료예정일", "시간순서", "약품명"], kind="mergesort")
            show_cols = ["병원명", "약품명", "복용시간대", "처방일(표시)", "종료예정일(표시)", "남은일수", "비고", "남은약"]
            with st.expander(f"🏥 병원: {h} — 약품 {len(sub)}건", expanded=True):
                st.dataframe(sub[show_cols].rename(columns={
                    "처방일(표시)": "처방일",
                    "종료예정일(표시)": "종료예정일"
                }), use_container_width=True)
    else:
        st.info("해당 대상자에 대한 병원 기록이 없습니다.")

# 대시보드 표(전체/필터 결과)
total_count = len(df_display) if not df_display.empty else 0
filtered_count = len(filtered_df) if not filtered_df.empty else 0
st.caption(f"필터링된 결과: **{filtered_count}건** / 전체: {total_count}건")

if not filtered_df.empty:
    tmp = filtered_df.copy()
    tmp["시간순서"] = tmp["복용시간대"].map(TIME_ORDER_MAP).fillna(999).astype(int)
    display_cols_main = ["이름", "병원명", "약품명", "복용시간대", "처방일", "복용일수", "종료예정일", "남은일수", "비고", "남은약"]
    tmp = tmp.sort_values(["이름", "병원명", "종료예정일", "시간순서", "약품명"], kind="mergesort")
    filtered_sorted = tmp[["기록ID"] + display_cols_main].copy()

    # 화면 표시용 날짜 포맷(메인 표에서는 기록ID 숨김)
    df_show = filtered_sorted.copy()
    df_show["처방일"] = df_show["처방일"].dt.strftime("%Y-%m-%d")
    df_show["종료예정일"] = df_show["종료예정일"].dt.strftime("%Y-%m-%d")
    st.dataframe(df_show[display_cols_main], use_container_width=True)

    # 다운로드(현재 필터 결과 기준)
    csv_bytes = filtered_sorted.to_csv(index=False, encoding="utf-8-sig").encode("utf-8-sig")
    st.download_button(
        "📥 (현재 보기 기준) 데이터를 엑셀로 내보내기",
        csv_bytes,
        "투약관리데이터_필터결과.csv",
        "text/csv",
        key="download-csv"
    )
else:
    st.info("표시할 데이터가 없습니다. (검색 조건을 확인해 주세요)")

# -------------------------------
# 🗑️ 삭제 도구 (현재 필터 결과 기준) — 전체 선택/해제 + 선택 유지
# -------------------------------
st.markdown("## 🗑️ 삭제 도구")

if filtered_df.empty:
    st.info("삭제할 대상이 없습니다. (검색 조건을 확인해 주세요)")
else:
    # 삭제 에디터용 데이터프레임: 현재 필터 결과만
    delete_df = filtered_sorted.copy()  # ['기록ID' + 표시 컬럼]
    delete_df = delete_df.rename(columns={
        "처방일": "처방일(표시용)",
        "종료예정일": "종료예정일(표시용)"
    })
    delete_df["처방일(표시용)"] = pd.to_datetime(delete_df["처방일(표시용)"]).dt.strftime("%Y-%m-%d")
    delete_df["종료예정일(표시용)"] = pd.to_datetime(delete_df["종료예정일(표시용)"]).dt.strftime("%Y-%m-%d")

    # ✅ 세션에 저장된 선택 상태로 '삭제' 체크 채워넣기
    sel_set = set(st.session_state.delete_selected_ids)
    delete_df.insert(1, "삭제", delete_df["기록ID"].isin(sel_set))

    # 상단 컨트롤: 전체 선택/해제 버튼 (세션에 직접 반영)
    bc1, bc2, bc3 = st.columns([1, 1, 3])
    with bc1:
        if st.button("✅ 전체 선택", use_container_width=True):
            st.session_state.delete_selected_ids = delete_df["기록ID"].tolist()
            st.rerun()
    with bc2:
        if st.button("↩️ 전체 해제", use_container_width=True):
            st.session_state.delete_selected_ids = []
            st.rerun()
    with bc3:
        st.caption("※ '전체 선택' 후 일부만 해제도 가능합니다. 선택은 화면 갱신 후에도 유지됩니다.")

    st.caption("아래 표에서 삭제할 행의 체크박스를 선택/해제한 뒤, '선택 행 삭제' 버튼을 누르세요.")
    edited = st.data_editor(
        delete_df,
        column_config={
            "삭제": st.column_config.CheckboxColumn(
                "삭제", help="삭제할 행에 체크", default=False
            ),
            "기록ID": st.column_config.TextColumn("기록ID", help="내부 식별자(읽기전용)"),
            "처방일(표시용)": st.column_config.DateColumn("처방일", format="YYYY-MM-DD", disabled=True),
            "종료예정일(표시용)": st.column_config.DateColumn("종료예정일", format="YYYY-MM-DD", disabled=True),
        },
        disabled=["기록ID", "이름", "병원명", "약품명", "복용시간대", "처방일(표시용)", "종료예정일(표시용)", "복용일수", "남은일수", "비고", "남은약"],
        use_container_width=True,
        key="delete_editor",
        hide_index=True
    )

    # ✅ 사용자가 체크/해제한 최신 상태를 세션에 반영 (rerun 되어도 유지)
    try:
        selected_now = edited.loc[edited["삭제"] == True, "기록ID"].tolist()
    except Exception:
        selected_now = []
    st.session_state.delete_selected_ids = selected_now

    # 선택 카운트 표시
    st.caption(f"현재 선택: {len(selected_now)}건 / 표시 중: {len(edited)}건")

    # 삭제 실행 UI
    col_d1, col_d2 = st.columns([1.2, 1])
    with col_d1:
        confirm = st.checkbox("정말 삭제하시겠습니까?", value=False)
    with col_d2:
        run_delete = st.button("🚨 선택 행 삭제", type="primary", use_container_width=True)

    # 복원(Undo)
    col_u1, col_u2 = st.columns([1, 1])
    with col_u1:
        can_undo = len(st.session_state.undo_stack) > 0
        if st.button("↩️ 마지막 삭제 복원", disabled=not can_undo, use_container_width=True):
            # 가장 최근 백업 복원
            st.session_state.data = ensure_schema(st.session_state.undo_stack.pop())
            save_data(st.session_state.data)
            st.success("마지막 삭제 작업을 복원했습니다.")
            st.rerun()
    with col_u2:
        st.caption("※ 복원은 같은 실행 세션 내에서만 가능")

    # 실제 삭제 처리
    if run_delete:
        selected_ids = list(st.session_state.delete_selected_ids)
        if not selected_ids:
            st.warning("삭제할 행을 선택해 주세요.")
        elif not confirm:
            st.warning("체크박스로 삭제 의사를 확인해 주세요.")
        else:
            # 백업 스택에 현재 데이터 저장(복원용)
            st.session_state.undo_stack.append(st.session_state.data.copy())

            before = len(st.session_state.data)
            st.session_state.data = st.session_state.data[~st.session_state.data["기록ID"].isin(selected_ids)].copy()
            after = len(st.session_state.data)
            removed = before - after

            save_data(st.session_state.data)
            # 삭제 후 선택 목록 초기화
            st.session_state.delete_selected_ids = []
            st.success(f"선택한 {removed}건을 삭제했습니다.")
            st.rerun()

# (옵션) 단일 대상자일 때 "이 사람 기록 전체 삭제"
if len(unique_names) == 1 and not filtered_df.empty:
    with st.expander(f"🧹 '{unique_names[0]}' 대상자 기록 일괄 삭제 (주의)", expanded=False):
        st.warning("이 기능은 현재 필터 결과에서 해당 대상자의 모든 기록을 삭제합니다. 신중히 사용하세요.")
        all_confirm = st.checkbox("정말 이 대상자의 모든 기록을 삭제합니다.", value=False)
        all_delete = st.button("🚨 이 대상자 기록 전체 삭제")
        if all_delete:
            if not all_confirm:
                st.warning("체크박스로 삭제 의사를 확인해 주세요.")
            else:
                # 백업
                st.session_state.undo_stack.append(st.session_state.data.copy())
                target = unique_names[0]
                before = len(st.session_state.data)
                st.session_state.data = st.session_state.data[st.session_state.data["이름"] != target].copy()
                after = len(st.session_state.data)
                removed = before - after
                save_data(st.session_state.data)
                # 선택 목록 초기화
                st.session_state.delete_selected_ids = []
                st.success(f"'{target}' 대상자의 기록 {removed}건을 삭제했습니다.")
                st.rerun()

# 마지막 상태 메시지 토스트
if st.session_state.last_status:
    st.toast(st.session_state.last_status)