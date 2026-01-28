# -*- coding: utf-8 -*-
"""
==========================================
복지시설 투약 관리 (모바일 대응 탭 UI) — app.py
(Microsoft Lists + OneDrive 버전)
==========================================

[설정 가이드 - .streamlit/secrets.toml]
---------------------------------------
[app]
password_hash = "pbkdf2_sha256$260000$SALT_BASE64$DERIVED_KEY_BASE64"
max_attempts = 10
lock_minutes = 3

[msgraph]
tenant_id     = "YOUR_TENANT_ID"
client_id     = "YOUR_APP_CLIENT_ID"
client_secret = "YOUR_APP_CLIENT_SECRET"
site_id       = "YOUR_SHAREPOINT_SITE_ID"
list_id       = "YOUR_LIST_ID"

[onedrive]
drive_id    = "YOUR_DRIVE_ID"
backup_path = "복지시설투약관리/medication_data.csv"

[주의]
- 이 앱은 "단일 비밀번호"를 공유하는 간편 보안 방식입니다.
  사용자별 접근제어/감사 기능은 제공하지 않으므로, 비밀번호 유출/공유에 취약할 수 있습니다.
- 데이터(CSV)는 앱과 동일 폴더에 캐시로 저장됩니다.
- 영구 저장/복구는 Microsoft Lists 및 OneDrive 파일을 사용합니다.
"""

import os
import time
import base64
import hashlib
import hmac
import uuid
from datetime import date, timedelta, datetime

import pandas as pd
import streamlit as st
import requests # pyright: ignore[reportMissingModuleSource]
import requests
# selenium 관련 임포트는 하단 RPA 함수 내부로 이동 (클라우드 환경 임포트 에러 방지)

# -------------------------------
# 기본 설정
# -------------------------------
st.set_page_config(page_title="복지시설 투약 관리", layout="wide")
st.title("💊 생활인 투약 관리 시스템 (Microsoft 365)")

# --- [필수 상수 정의] 세션 초기화 등에 사용됨 ---
REQUIRED_COLS = [
    "기록ID", "이름", "병원명", "약품명", "처방일", "복용일수",
    "종료예정일", "비고", "남은약", "복용시간대"
]

TIME_OPTIONS = ["아침약", "점심약", "저녁약", "아침 식전약", "저녁 식전약", "취침전약"]

TIME_ORDER_MAP = {
    "아침 식전약": 0, "아침약": 1, "점심약": 2,
    "저녁 식전약": 3, "저녁약": 4, "취침전약": 5,
}

# (선택) 입력 필드 최대 폭 조정: 모바일에서도 과도한 넓이를 방지
st.markdown(
    """
<style>
/* password input 최대 폭 */
section[data-testid="stTextInput"] input[type="password"] {
  max-width: 480px;
}

/* 일반 텍스트 입력/숫자 입력의 최대 폭도 적절히 제한 */
section[data-testid="stTextInput"] input[type="text"],
section[data-testid="stNumberInput"] input[type="number"],
section[data-testid="stDateInput"] input[type="text"],
textarea {
  max-width: 520px;
}

/* 탭이 모바일에서 붙지 않도록 여백 */
div[data-baseweb="tab-list"] {
  flex-wrap: wrap;
  gap: 6px;
}
</style>
""",
    unsafe_allow_html=True,
)

DB_FILE = "medication_data.csv"
EXCEL_FILE_PATH = r"\\ep_nas1\만성요양과\★2026년\01. 인원관리(동일지, 호실배치, 종합관리)\01. 호실배치, 동일지, 종합관리, 식수인원\01. 종합관리(만성요양과).xlsx"

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
    return (
        f"pbkdf2_sha256${iterations}$"
        f"{base64.b64encode(salt).decode()}$"
        f"{base64.b64encode(dk).decode()}"
    )


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

# --- 상태값 초기화 (최상단 배치) ---
if "auth_ok" not in st.session_state:
    st.session_state.auth_ok = False
if "fail_count" not in st.session_state:
    st.session_state.fail_count = 0
if "locked_until" not in st.session_state:
    st.session_state.locked_until = 0.0
if "last_status" not in st.session_state:
    st.session_state.last_status = ""
if "search_text" not in st.session_state:
    st.session_state.search_text = ""
if "search_select" not in st.session_state:
    st.session_state.search_select = ""
if "search_active" not in st.session_state:
    st.session_state.search_active = False
if "undo_stack" not in st.session_state:
    st.session_state.undo_stack = []
if "delete_selected_ids" not in st.session_state:
    st.session_state.delete_selected_ids = []
if "data" not in st.session_state:
    # 헬퍼 함수가 정의된 후에 호출하기 위해 아래로 미루거나 여기서 기본값 설정
    st.session_state.data = pd.DataFrame(columns=REQUIRED_COLS)

# --- 관리자 도구(해시 생성기): '정말 필요할 때'만 보여주기 ---
def render_admin_tools():
    if PASSWORD_HASH:
        return
    
    with st.expander("🔧 관리자 도구: 비밀번호 해시 생성기 (초기 설정용)", expanded=True):
        st.warning("⚠️ 현재 `password_hash` 설정이 비어 있습니다. (로그인 불가)")
        
        # 클라우드 vs 로컬 안내 (로컬 파일 존재 여부로 추측)
        if not os.path.exists(".streamlit/secrets.toml"):
            st.info(
                "💡 **Streamlit Cloud(웹)**에서 보시는 경우:\n\n"
                "로컬의 `secrets.toml` 파일은 보안상 웹으로 전송되지 않습니다. "
                "웹 대시보드의 **[Settings] -> [Secrets]** 메뉴에 아래의 해시 설정을 직접 붙여넣어야 합니다."
            )
        else:
            st.info(
                "💡 **로컬 환경**에서 보시는 경우:\n\n"
                "프로젝트 폴더 내 `.streamlit/secrets.toml` 파일을 열어 `password_hash` 값을 업데이트하세요."
            )

        st.markdown("---")
        st.caption("① 평문 비밀번호를 입력하면 해시를 생성합니다. ② 생성된 문자열을 설정(Secrets)에 저장하세요.")
        col1, col2 = st.columns([2, 1])
        with col1:
            plain = st.text_input("평문 비밀번호 입력(표시됨)", value="", type="default", key="admin_plain_pwd")
        with col2:
            iters = st.number_input("iterations", min_value=100_000, value=260_000, step=10_000, key="admin_iters")
        
        if st.button("해시 생성하기", key="btn_gen_hash"):
            if plain:
                def _make_hash(p: str, iterations: int = 260_000) -> str:
                    salt = os.urandom(16)
                    dk = hashlib.pbkdf2_hmac("sha256", p.encode("utf-8"), salt, iterations)
                    import base64 as b64
                    return f"pbkdf2_sha256${iterations}${b64.b64encode(salt).decode()}${b64.b64encode(dk).decode()}"
                hashed = _make_hash(plain, int(iters))
                st.code(hashed, language="text")
                st.success("위 문자열을 [app] 섹션의 password_hash 항목에 저장한 뒤 앱을 새로고침하세요.")
            else:
                st.warning("평문 비밀번호를 입력해 주세요.")

    with st.expander("☁️ Microsoft 365 연동 도우미 (ID 자동 찾기)", expanded=False):
        st.markdown("""
        이 도구는 **Client Secret**을 사용하여 SharePoint 사이트와 목록의 ID를 자동으로 찾아줍니다.
        1. Azure 포털에서 생성한 **Client Secret**을 아래에 입력하세요.
        2. [연동 테스트 및 ID 찾기] 버튼을 누르세요.
        """)
        
        test_secret = st.text_input("Client Secret 입력", type="password", key="test_secret")
        test_site_url = st.text_input("SharePoint 사이트 주소", value="https://eunpyongorkr.sharepoint.com/sites/T-Severely", key="test_site_url")
        
        if st.button("🚀 연동 테스트 및 ID 찾기", use_container_width=True):
            if not test_secret:
                st.warning("Client Secret을 입력해 주세요.")
            else:
                with st.spinner("Microsoft Graph API 연결 중..."):
                    # 토큰 획득 테스트
                    t_id = st.secrets["msgraph"]["tenant_id"]
                    c_id = st.secrets["msgraph"]["client_id"]
                    
                    token_url = f"https://login.microsoftonline.com/{t_id}/oauth2/v2.0/token"
                    payload = {
                        "client_id": c_id,
                        "scope": "https://graph.microsoft.com/.default",
                        "client_secret": test_secret,
                        "grant_type": "client_credentials",
                    }
                    try:
                        r = requests.post(token_url, data=payload, timeout=10)
                        res = r.json()
                        if "error" in res:
                            st.error(f"토큰 획득 실패: {res.get('error_description')}")
                        else:
                            st.success("✅ 인증 성공! (토큰 획득 완료)")
                            token = res["access_token"]
                            headers = {"Authorization": f"Bearer {token}"}
                            
                            # 1. Site ID 찾기
                            # URL에서 호스트와 경로 추출
                            from urllib.parse import urlparse
                            parsed = urlparse(test_site_url)
                            host = parsed.netloc
                            path = parsed.path
                            
                            site_query = f"https://graph.microsoft.com/v1.0/sites/{host}:{path}"
                            sr = requests.get(site_query, headers=headers, timeout=10)
                            sres = sr.json()
                            
                            if "id" in sres:
                                found_site_id = sres["id"]
                                st.write(f"📍 **찾은 Site ID:**")
                                st.code(found_site_id)
                                
                                # 2. List 찾기
                                list_query = f"https://graph.microsoft.com/v1.0/sites/{found_site_id}/lists"
                                lr = requests.get(list_query, headers=headers, timeout=10)
                                lres = lr.json()
                                
                                if "value" in lres:
                                    st.write("📋 **사이트 내 목록 리스트:**")
                                    found_lists = lres["value"]
                                    if not found_lists:
                                        st.info("사이트에 목록이 없습니다. Microsoft Lists에서 새 목록을 만들어 주세요.")
                                    for l in found_lists:
                                        with st.container():
                                            col_a, col_b = st.columns([1, 2])
                                            col_a.write(f"**{l['displayName']}**")
                                            col_b.code(l['id'])
                            else:
                                st.error("사이트 ID를 찾을 수 없습니다. 주소를 확인해 주세요.")
                                st.json(sres)
                    except Exception as e:
                        st.error(f"연결 오류 발생: {e}")


# --- 로그인 폼 ---
def login_form(now_ts: float, align: str = "center", width_fraction: float = 1/3):
    st.subheader("🔐 접근 비밀번호를 입력하세요.")

    width_fraction = max(0.2, min(width_fraction, 1.0))
    if align == "left":
        left_col, right_sp = st.columns([width_fraction, 1 - width_fraction])
        target_col = left_col
    else:
        side = (1 - width_fraction) / 2
        _, target_col, _ = st.columns([side, width_fraction, side])

    with target_col:
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
            ok = verify_password(pwd, PASSWORD_HASH)
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


# --- 게이트 ---
def render_gate_and_stop_if_not_authenticated():
    now_ts = time.time()
    # 잠금 상태
    if st.session_state.locked_until and now_ts < st.session_state.locked_until:
        left = int((st.session_state.locked_until - now_ts) // 60) + 1
        st.error(f"보안 잠금 중입니다. {left}분 후 다시 시도하세요.")
        render_admin_tools()
        st.stop()

    if not st.session_state.auth_ok:
        login_form(now_ts, align="center", width_fraction=1/3)
        render_admin_tools()
        st.stop()

# -------------------------------------------------------------------
# (B) 투약 관리 본 기능
# -------------------------------------------------------------------
def generate_id() -> str:
    """레코드 고유 ID"""
    return uuid.uuid4().hex


# =========================
# Microsoft Graph (Lists + OneDrive) 헬퍼
# =========================

def _ms_cfg():
    try:
        cfg = dict(st.secrets.get("msgraph", {}))
        return cfg
    except Exception:
        return {}

def _onedrive_cfg():
    try:
        cfg = dict(st.secrets.get("onedrive", {}))
        return cfg
    except Exception:
        return {}

def _is_ms_configured():
    cfg = _ms_cfg()
    required = ["tenant_id", "client_id", "client_secret", "site_id", "list_id"]
    return all(cfg.get(k) and str(cfg.get(k)).strip() for k in required)

def _is_onedrive_configured():
    cfg = _onedrive_cfg()
    required = ["drive_id"]
    return all(cfg.get(k) and str(cfg.get(k)).strip() for k in required)

def _get_token():
    # 간단 캐시
    if "ms_token" in st.session_state and st.session_state.get("ms_token_exp", 0) > time.time() + 60:
        return st.session_state["ms_token"]
    
    if not _is_ms_configured():
        raise RuntimeError("Microsoft Graph 설정이 불완전합니다. (secrets.toml 확인 필요)")

    cfg = _ms_cfg()
    tenant = cfg["tenant_id"]
    client_id = cfg["client_id"]
    client_secret = cfg["client_secret"]
    token_url = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
    data = {
        "client_id": client_id,
        "client_secret": client_secret,
        "grant_type": "client_credentials",
        "scope": "https://graph.microsoft.com/.default",
    }
    r = requests.post(token_url, data=data, timeout=30)
    if not r.ok:
        raise RuntimeError(f"토큰 발급 실패: {r.status_code} {r.text}")
    tok = r.json()
    st.session_state["ms_token"] = tok["access_token"]
    st.session_state["ms_token_exp"] = time.time() + tok.get("expires_in", 3599)
    return tok["access_token"]

def _gheaders(json=True):
    hdrs = {"Authorization": f"Bearer {_get_token()}"}
    if json:
        hdrs["Content-Type"] = "application/json"
    return hdrs

# ----- Microsoft List 필드 매핑 -----
# DataFrame(KR) <-> Microsoft List(EN internal)
FIELD_MAP = {
    "기록ID": "RecordID",
    "이름": "Name",
    "병원명": "Hospital",
    "약품명": "Drug",
    "복용시간대": "TimeSlot",
    "처방일": "StartDate",
    "복용일수": "Days",
    "종료예정일": "EndDate",
    "비고": "Memo",
    "남은약": "LeftPills",
}
REVERSE_FIELD_MAP = {v: k for k, v in FIELD_MAP.items()}

def _list_fetch_all_items():
    """Microsoft List 아이템 전체 조회 (expand=fields)."""
    cfg = _ms_cfg()
    site_id = cfg["site_id"]
    list_id = cfg["list_id"]
    url = f"https://graph.microsoft.com/v1.0/sites/{site_id}/lists/{list_id}/items?expand=fields&$top=2000"
    items = []
    while True:
        r = requests.get(url, headers=_gheaders(), timeout=30)
        if not r.ok:
            raise RuntimeError(f"List 불러오기 실패: {r.status_code} {r.text}")
        data = r.json()
        items.extend(data.get("value", []))
        next_link = data.get("@odata.nextLink")
        if not next_link:
            break
        url = next_link
    return items

def _list_clear_all_items():
    """모든 아이템 삭제 (소량 데이터 가정)."""
    cfg = _ms_cfg()
    site_id = cfg["site_id"]
    list_id = cfg["list_id"]
    items = _list_fetch_all_items()
    for it in items:
        item_id = it.get("id")
        if not item_id:
            continue
        url = f"https://graph.microsoft.com/v1.0/sites/{site_id}/lists/{list_id}/items/{item_id}"
        r = requests.delete(url, headers=_gheaders(), timeout=30)
        if not r.ok and r.status_code != 404:
            raise RuntimeError(f"List 아이템 삭제 실패: {r.status_code} {r.text}")

def _list_add_item(fields: dict):
    """한 건 추가: fields 사전은 Microsoft List 내부 필드명 기준."""
    cfg = _ms_cfg()
    site_id = cfg["site_id"]
    list_id = cfg["list_id"]
    url = f"https://graph.microsoft.com/v1.0/sites/{site_id}/lists/{list_id}/items"
    payload = {"fields": fields}
    r = requests.post(url, headers=_gheaders(), json=payload, timeout=30)
    if not r.ok:
        raise RuntimeError(f"List 아이템 추가 실패: {r.status_code} {r.text}")
    return r.json()

def _list_replace_all(df: pd.DataFrame):
    """
    ⚠️ 간단 구현: 리스트 전체를 '초기화하고' DataFrame 내용을 모두 다시 추가합니다.
    - 소규모 데이터 기준으로 충분 (권장: 수백 건 이하)
    - 대규모 데이터면 Upsert(키=RecordID) 로직으로 최적화 필요
    """
    # 1) 모두 삭제
    _list_clear_all_items()

    # 2) 모두 추가
    if df is None or df.empty:
        return

    # 날짜는 'YYYY-MM-DD' 문자열로
    out = df.copy()
    for col in ["처방일", "종료예정일"]:
        if col in out.columns:
            out[col] = pd.to_datetime(out[col], errors="coerce").dt.strftime("%Y-%m-%d")
    out = out.fillna("")

    for _, row in out.iterrows():
        fields = {}
        for kr, en in FIELD_MAP.items():
            val = row.get(kr, "")
            # 숫자 캐스팅
            if kr in ["복용일수", "남은약"]:
                try:
                    val = int(val) if str(val).strip() != "" else 0
                except Exception:
                    val = 0
            fields[en] = val
        # Title은 표시용 → 이름으로
        fields["Title"] = str(row.get("이름", "") or "")
        _list_add_item(fields)

def _list_to_dataframe(items) -> pd.DataFrame:
    """List 아이템(JSON) -> 앱 DataFrame(한국어 스키마)."""
    rows = []
    for it in items:
        f = it.get("fields", {})
        row = {}
        for kr, en in FIELD_MAP.items():
            row[kr] = f.get(en, "")
        rows.append(row)
    df = pd.DataFrame(rows, columns=REQUIRED_COLS)
    return df

def _onedrive_upload_bytes(content: bytes, path: str):
    """OneDrive에 파일 업로드(덮어쓰기)."""
    od = _onedrive_cfg()
    drive_id = od["drive_id"]
    # 경로 내 공백/한글 허용. Graph는 UTF-8 path OK
    url = f"https://graph.microsoft.com/v1.0/drives/{drive_id}/root:/{path}:/content"
    r = requests.put(url, headers={"Authorization": f"Bearer {_get_token()}"}, data=content, timeout=60)
    if not r.ok:
        raise RuntimeError(f"OneDrive 업로드 실패: {r.status_code} {r.text}")

def _onedrive_download_bytes(path: str) -> bytes:
    """OneDrive에서 파일 다운로드(바이트). 없으면 예외."""
    od = _onedrive_cfg()
    drive_id = od["drive_id"]
    url = f"https://graph.microsoft.com/v1.0/drives/{drive_id}/root:/{path}:/content"
    r = requests.get(url, headers={"Authorization": f"Bearer {_get_token()}"}, timeout=60)
    if not r.ok:
        raise RuntimeError(f"OneDrive 다운로드 실패: {r.status_code} {r.text}")
    return r.content

# =========================
# 스키마 & 저장/로드
# =========================
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
    """
    1) 로컬 CSV 우선 로드
    2) 실패/없음 -> Microsoft List 폴백
    3) 그래도 실패 -> OneDrive 백업 CSV 폴백
    """
    # 1) 로컬 CSV
    if os.path.exists(DB_FILE):
        try:
            df = pd.read_csv(DB_FILE, encoding="utf-8-sig")
            return ensure_schema(df)
        except Exception as e:
            st.warning(f"로컬 CSV 로드 실패: {e}")

    # 2) Microsoft List 폴백
    if _is_ms_configured():
        try:
            items = _list_fetch_all_items()
            if items:
                df = _list_to_dataframe(items)
                df = ensure_schema(df)
                # 로컬 캐시 저장
                try:
                    df.to_csv(DB_FILE, index=False, encoding="utf-8-sig")
                except Exception as e:
                    st.info(f"로컬 캐시 저장 실패(무시 가능): {e}")
                return df
        except Exception as e:
            st.warning(f"Microsoft List 로드 실패: {e}")
    else:
        st.info("Microsoft List 설정이 없어 로컬 전용 모드로 동작합니다.")

    # 3) OneDrive 백업 CSV 폴백
    if _is_onedrive_configured():
        try:
            od = _onedrive_cfg()
            backup_path = od.get("backup_path", "복지시설투약관리/medication_data.csv")
            content = _onedrive_download_bytes(backup_path)
            from io import BytesIO, StringIO
            csv_text = content.decode("utf-8-sig")
            df = pd.read_csv(StringIO(csv_text))
            df = ensure_schema(df)
            # 로컬 캐시 저장
            try:
                df.to_csv(DB_FILE, index=False, encoding="utf-8-sig")
            except Exception as e:
                st.info(f"로컬 캐시 저장 실패(무시 가능): {e}")
            return df
        except Exception as e:
            st.error(f"OneDrive 백업 로드 실패: {e}")
    
    return ensure_schema(pd.DataFrame(columns=REQUIRED_COLS))


def save_data(df: pd.DataFrame):
    """
    로컬 CSV 저장 + Microsoft List 전체 반영 + OneDrive 백업 업로드
    - 원격 저장 실패 시 경고만 표시하고 계속
    """
    # 1) 로컬 캐시
    try:
        df_to_save = ensure_schema(df.copy())
        df_to_save.to_csv(DB_FILE, index=False, encoding="utf-8-sig")
    except Exception as e:
        st.warning(f"로컬 CSV 저장 중 경고: {e}")
        df_to_save = ensure_schema(df.copy())  # 계속 진행

    # 2) Microsoft List 반영 (전체 교체)
    if _is_ms_configured():
        try:
            _list_replace_all(df_to_save)
        except Exception as e:
            st.error(f"Microsoft List 저장 실패: {e}")

    # 3) OneDrive 백업 업로드
    if _is_onedrive_configured():
        try:
            od = _onedrive_cfg()
            backup_path = od.get("backup_path", "복지시설투약관리/medication_data.csv")
            csv_bytes = df_to_save.to_csv(index=False, encoding="utf-8-sig").encode("utf-8-sig")
            _onedrive_upload_bytes(csv_bytes, backup_path)
        except Exception as e:
            st.error(f"OneDrive 백업 업로드 실패: {e}")

# -------------------------------
# (B) 로컬 파일 사용 옵션 추가
# -------------------------------

def load_local_data(file_path: str) -> pd.DataFrame:
    """
    로컬 파일에서 데이터를 로드합니다.
    """
    try:
        if os.path.exists(file_path):
            return pd.read_excel(file_path)
        else:
            st.error(f"지정된 파일을 찾을 수 없습니다: {file_path}")
            return pd.DataFrame(columns=REQUIRED_COLS)
    except Exception as e:
        st.error(f"로컬 파일을 로드하는 중 오류가 발생했습니다: {e}")
        return pd.DataFrame(columns=REQUIRED_COLS)

def save_local_data(df: pd.DataFrame, file_path: str):
    """
    로컬 파일에 데이터를 저장합니다.
    """
    try:
        df.to_excel(file_path, index=False)
        st.success("데이터가 로컬 파일에 저장되었습니다.")
    except Exception as e:
        st.error(f"로컬 파일에 데이터를 저장하는 중 오류가 발생했습니다: {e}")

# -------------------------------
# (C) 데이터 소스 선택 및 로드
# -------------------------------

data_source = st.radio("데이터 소스 선택", ("Microsoft Lists/OneDrive", "로컬 파일"))

if data_source == "로컬 파일":
    local_file_path = st.text_input("로컬 파일 경로를 입력하세요", EXCEL_FILE_PATH, key="local_file_path")
    if st.button("로컬 데이터 로드"):
        data = load_local_data(local_file_path)
else:
    # 기존 Microsoft Lists/OneDrive 로직 유지
    data = pd.read_csv(DB_FILE)  # 예시로 기존 CSV 로드 로직 유지

# 데이터 저장 버튼 추가
if data_source == "로컬 파일" and st.button("로컬 데이터 저장"):
    save_local_data(data, local_file_path)

# =========================
# 메인 실행 흐름 (포괄적 예외 처리)
# =========================

# -------------------------------------------------------------------
# (C) 희망이음 RPA 연동 헬퍼
# -------------------------------------------------------------------
def get_driver_connected():
    """이미 실행 중인 디버깅 브라우저(9222)에 연결"""
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
    except ImportError:
        st.error("Selenium 라이브러리가 설치되지 않았습니다.")
        return None

    chrome_options = Options()
    chrome_options.add_experimental_option("debuggerAddress", "127.0.0.1:9222")
    try:
        driver = webdriver.Chrome(options=chrome_options)
        return driver
    except Exception as e:
        st.error(f"브라우저 연결 실패: {e}")
        st.info("9222 포트로 실행된 크롬 창이 있는지 확인해 주세요.")
        return None

def scrape_ssis_treatment_status(driver, progress_bar=None, status_text=None):
    """희망이음 진료 현황 테이블 데이터 추출 (탭 자동 전환 + iFrame 탐색)"""
    try:
        from selenium.webdriver.common.by import By
        from selenium.webdriver.support.ui import WebDriverWait
        from selenium.webdriver.support import expected_conditions as EC

        if status_text: status_text.info("🔍 희망이음 탭을 찾는 중...")
        if progress_bar: progress_bar.progress(30)

        # 1. 모든 탭을 순회하며 ssis.go.kr이 있는 탭 찾기
        original_window = driver.current_window_handle
        target_window = None
        
        for window_handle in driver.window_handles:
            driver.switch_to.window(window_handle)
            if "ssis.go.kr" in driver.current_url:
                target_window = window_handle
                break
        
        if not target_window:
            driver.switch_to.window(original_window)
            return None, "희망이음(ssis.go.kr) 탭을 찾을 수 없습니다. 희망이음 사이트가 열려있는지 확인해 주세요."
        
        driver.switch_to.window(target_window)
        
        if status_text: status_text.info("📋 표 데이터를 찾는 중...")
        if progress_bar: progress_bar.progress(50)

        # 2. 메인 페이지에서 테이블 찾기
        def find_tables_recursive(context):
            """재귀적으로 iFrame 내부까지 테이블 탐색"""
            tables = []
            try:
                # 현재 컨텍스트에서 테이블 찾기
                tables.extend(context.find_elements(By.TAG_NAME, "table"))
                
                # iFrame 탐색
                iframes = context.find_elements(By.TAG_NAME, "iframe")
                for iframe in iframes:
                    try:
                        driver.switch_to.frame(iframe)
                        tables.extend(find_tables_recursive(driver))
                        driver.switch_to.parent_frame()
                    except:
                        driver.switch_to.parent_frame()
                        continue
            except:
                pass
            return tables

        all_tables = find_tables_recursive(driver)

        if not all_tables:
            return None, "화면에서 테이블을 찾을 수 없습니다. '대상자 진료 현황' 페이지가 맞는지 확인해 주세요."

        # 3. 가장 큰 테이블 선택 (데이터가 가장 많은 것)
        target_table = None
        max_rows = 0
        for t in all_tables:
            try:
                rows = t.find_elements(By.TAG_NAME, "tr")
                if len(rows) > max_rows:
                    max_rows = len(rows)
                    target_table = t
            except:
                continue

        if not target_table or max_rows < 2:  # 최소 헤더 + 1행 이상
            return None, "유효한 데이터 테이블을 찾을 수 없습니다."

        if status_text: status_text.info("⚙️ 표 데이터를 읽고 분석하는 중...")
        if progress_bar: progress_bar.progress(80)

        # 4. 테이블 파싱
        html_content = target_table.get_attribute('outerHTML')
        dfs = pd.read_html(html_content)
        if not dfs:
            return None, "테이블 파싱에 실패했습니다."

        if progress_bar: progress_bar.progress(100)
        
        # 원래 탭으로 복귀
        driver.switch_to.window(original_window)
        
        return dfs[0], "성공"

    except Exception as e:
        # 오류 발생 시에도 원래 탭으로 복귀 시도
        try:
            driver.switch_to.window(original_window)
        except:
            pass
        return None, f"스크래핑 오류: {e}"

def load_excel_from_network(file_path: str) -> tuple:
    """
    네트워크 경로에서 Excel 파일을 읽어옵니다.
    Returns: (DataFrame or None, error_message or None)
    """
    try:
        if not os.path.exists(file_path):
            return None, f"파일을 찾을 수 없습니다: {file_path}"
        
        # Excel 파일 읽기 (첫 번째 시트)
        df = pd.read_excel(file_path, engine='openpyxl')
        
        if df.empty:
            return None, "파일이 비어있습니다."
        
        return df, None
        
    except PermissionError:
        return None, "파일 접근 권한이 없습니다. 네트워크 드라이브 연결을 확인해주세요."
    except Exception as e:
        return None, f"파일 읽기 오류: {str(e)}"


def main():
    # 1. 인증 게이트
    render_gate_and_stop_if_not_authenticated()

    # 2. 사이드바 (로그아웃 & 버전)
    with st.sidebar:
        if st.button("로그아웃", key="sidebar_logout"):
            st.session_state.auth_ok = False
            st.rerun()
        st.write("버전: 2.9 (엑셀 가져오기 기능 추가)")

    # 3. 데이터 로드
    if "data" not in st.session_state or st.session_state.data.empty:
        st.session_state.data = load_data()

    # 4. 상단 탭 정의
    tab_reg, tab_dash, tab_rpa, tab_excel, tab_del = st.tabs(["등록검색", "대시보드", "희망이음연동", "엑셀가져오기", "데이터삭제"])

    # -------------------------------------------------------------------
    # 탭 1: 등록/검색 구현
    # -------------------------------------------------------------------
    with tab_reg:
        st.subheader("1. 신규 투약 등록 및 대상자 검색")
        with st.form("register_form_main", clear_on_submit=True):
            col1, col2 = st.columns(2)
            with col1:
                input_name = st.text_input("생활인 성명", value="")
                input_med_name = st.text_input("약품명", value="")
                input_time_slot = st.selectbox("복용 시간대", options=TIME_OPTIONS, index=0)
                input_left_amount = st.number_input("남은 약 수량", min_value=0, value=0)
            with col2:
                input_hospital = st.text_input("병원/진료과", value="")
                input_start_date = st.date_input("처방일", value=date.today())
                input_days = st.number_input("복용 일수", min_value=1, value=30)
                input_memo = st.text_area("비고/특이사항", value="")

            submitted = st.form_submit_button("등록하기", use_container_width=True)

        if submitted:
            name = (input_name or "").strip()
            hospital = (input_hospital or "").strip()
            med_name = (input_med_name or "").strip()
            time_slot = (input_time_slot or "").strip()

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
                    "비고": (input_memo or "").strip(),
                    "남은약": int(input_left_amount),
                }])
                st.session_state.data = ensure_schema(pd.concat([st.session_state.data, new_row], ignore_index=True))
                save_data(st.session_state.data)
                st.session_state.last_status = f"✅ '{name}'님의 투약 정보가 성공적으로 저장되었습니다!"
                st.success(st.session_state.last_status)

        st.markdown("---")
        st.subheader("대상자 검색")

        names_list = sorted([n for n in st.session_state.data["이름"].dropna().unique() if n != ""])

        c1, c2 = st.columns(2)
        with c1:
            st.session_state.search_text = st.text_input(
                "이름(부분검색 가능)", value=st.session_state.search_text, placeholder="예: 홍길동", key="search_text_main"
            )
        with c2:
            st.session_state.search_select = st.selectbox(
                "이름(목록에서 선택)",
                options=[""] + names_list,
                index=([""] + names_list).index(st.session_state.search_select)
                if st.session_state.search_select in ([""] + names_list)
                else 0,
                key="search_select_main",
            )

        bc1, bc2, bc3 = st.columns([1, 1, 2])
        with bc1:
            if st.button("검색 적용", use_container_width=True, key="btn_apply_search"):
                st.session_state.search_active = True
                st.rerun()
        with bc2:
            if st.button("검색 해제(전체 보기)", use_container_width=True, key="btn_clear_search"):
                st.session_state.search_text = ""
                st.session_state.search_select = ""
                st.session_state.search_active = False
                st.session_state.delete_selected_ids = []
                st.rerun()
        with bc3:
            st.caption("※ '검색 적용'을 눌러야 필터가 반영됩니다.")

    # -------------------------------
    # 공통: 필터링 로직 (모든 탭에서 동일)
    # -------------------------------
    df_display = ensure_schema(st.session_state.data.copy())
    df_display["남은일수"] = 0  # 기본값 보장 (KeyError 방지)

    if not df_display.empty:
        today_ts = pd.to_datetime(date.today())
        df_display["남은일수"] = (df_display["종료예정일"] - today_ts).dt.days

    filtered_df = df_display.copy()

    selected_name = (st.session_state.search_select or "").strip()
    typed_query = (st.session_state.search_text or "").strip()

    if st.session_state.search_active and (selected_name or typed_query):
        if selected_name:
            filtered_df = filtered_df[filtered_df["이름"] == selected_name]
        elif typed_query:
            mask = filtered_df["이름"].str.contains(typed_query, case=False, na=False)
            filtered_df = filtered_df[mask]

    # 공통 정렬본
    if not filtered_df.empty:
        tmp = filtered_df.copy()
        tmp["시간순서"] = tmp["복용시간대"].map(TIME_ORDER_MAP).fillna(999).astype(int)
        display_cols_main = ["이름", "병원명", "약품명", "복용시간대", "처방일", "복용일수", "종료예정일", "남은일수", "비고", "남은약"]
        tmp = tmp.sort_values(["이름", "병원명", "종료예정일", "시간순서", "약품명"], kind="mergesort")
        filtered_sorted = tmp[["기록ID"] + display_cols_main].copy()
    else:
        filtered_sorted = pd.DataFrame(columns=["기록ID", "이름", "병원명", "약품명", "복용시간대", "처방일", "복용일수", "종료예정일", "남은일수", "비고", "남은약"])

    # -------------------------------------------------------------------
    # 탭 2: 대시보드
    # -------------------------------------------------------------------
    with tab_dash:
        st.subheader("대상자 투약 현황 대시보드")

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
            # 화면 표시용 날짜 포맷(메인 표에서는 기록ID 숨김)
            df_show = filtered_sorted.copy()
            df_show["처방일"] = df_show["처방일"].dt.strftime("%Y-%m-%d")
            df_show["종료예정일"] = df_show["종료예정일"].dt.strftime("%Y-%m-%d")
            st.dataframe(
                df_show[["이름", "병원명", "약품명", "복용시간대", "처방일", "복용일수", "종료예정일", "남은일수", "비고", "남은약"]],
                use_container_width=True
            )

            # 다운로드(현재 필터 결과 기준) — CSV
            csv_bytes = filtered_sorted.to_csv(index=False, encoding="utf-8-sig").encode("utf-8-sig")
            st.download_button(
                "📥 (현재 보기 기준) 데이터를 CSV로 내보내기",
                csv_bytes,
                "투약관리데이터_필터결과.csv",
                "text/csv",
                key="download-csv"
            )
        else:
            st.info("표시할 데이터가 없습니다. (검색 조건을 확인해 주세요)")

    # -------------------------------------------------------------------
    # 탭 3: 희망이음 연동 (RPA)
    # -------------------------------------------------------------------
    with tab_rpa:
        st.subheader("희망이음 데이터 자동 가져오기 (반자동)")
        
        with st.expander("ℹ️ 실행 전 준비사항 (필독)", expanded=True):
            st.markdown(f"""
            1.  **크롬 종료**: 열려있는 모든 크롬 창을 닫아주세요.
            2.  **디버깅 모드 실행**: 아래 명령어를 복사하여 [윈도우 키 + R] -> `cmd` 입력 후 실행하세요.
                ```powershell
                chrome.exe --remote-debugging-port=9222 --user-data-dir="C:\\sel_temp"
                ```
            3.  **로그인**: 새로 열린 크롬 창에서 [희망이음](https://www.ssis.go.kr)에 접속하여 로그인 및 간편인증을 완료하세요.
            4.  **페이지 이동**: '대상자 진료 현황' 메뉴까지 수동으로 이동하세요.
            """)

        col_r1, col_r2 = st.columns([1, 1])
        with col_r1:
            if st.button("🔍 현재 브라우저에서 데이터 긁어오기", use_container_width=True):
                # 진행 표시를 위한 컨테이너
                prog_bar = st.progress(0)
                stat_msg = st.empty()
                
                stat_msg.info("🔗 브라우저 연결 시도 중...")
                prog_bar.progress(20)
                
                driver = get_driver_connected()
                if driver:
                    df_scraped, msg = scrape_ssis_treatment_status(driver, progress_bar=prog_bar, status_text=stat_msg)
                    if df_scraped is not None:
                        st.session_state.scraped_df = df_scraped
                        stat_msg.success(f"✅ 데이터 추출 성공! ({len(df_scraped)}건)")
                    else:
                        stat_msg.error(msg)
                    driver.quit()
                else:
                    prog_bar.empty()
                    # get_driver_connected 내부에서 이미 에러 메시지를 표시함

        if "scraped_df" in st.session_state:
            st.write("### 📋 추출된 데이터 미리보기")
            st.dataframe(st.session_state.scraped_df, use_container_width=True)
            
            st.info("💡 위 데이터 중 '성명', '병원명', '약품명' 등이 올바른지 확인하세요.")
            
            with st.form("import_form"):
                st.markdown("#### 데이터 매핑 설정")
                col_m1, col_m2 = st.columns(2)
                # 희망이음 테이블 컬럼명에 맞춰 기본값 설정 (현장 상황에 따라 수정 필요)
                all_cols = st.session_state.scraped_df.columns.tolist()
                
                with col_m1:
                    col_name = st.selectbox("성명 컬럼", options=all_cols, index=all_cols.index("이름") if "이름" in all_cols else 0)
                    col_hospital = st.selectbox("병원명 컬럼", options=all_cols, index=all_cols.index("기관명") if "기관명" in all_cols else 0)
                with col_m2:
                    col_drug = st.selectbox("약품명 컬럼", options=all_cols, index=all_cols.index("약품명") if "약품명" in all_cols else 0)
                    col_date = st.selectbox("진료일/처방일 컬럼", options=all_cols, index=0)
                
                import_submit = st.form_submit_button("🚀 현재 시스템으로 가져오기 (등록)", use_container_width=True)
                
                if import_submit:
                    new_rows = []
                    for _, row in st.session_state.scraped_df.iterrows():
                        # 데이터 전처리 및 매핑
                        name = str(row[col_name])
                        hospital = str(row[col_hospital])
                        drug = str(row[col_drug])
                        # 날짜 처리 (문자열 -> datetime)
                        try:
                            p_date = pd.to_datetime(row[col_date])
                        except:
                            p_date = datetime.today()
                        
                        # 기본 "아침약", 30일 복용으로 가등록 (추후 수정 가능)
                        new_rows.append({
                            "기록ID": generate_id(),
                            "이름": name,
                            "병원명": hospital,
                            "약품명": drug,
                            "복용시간대": "아침약",
                            "처방일": p_date,
                            "복용일수": 30,
                            "종료예정일": p_date + timedelta(days=30),
                            "비고": "희망이음 연동 수집",
                            "남은약": 0
                        })
                    
                    if new_rows:
                        new_df = pd.DataFrame(new_rows)
                        st.session_state.data = ensure_schema(pd.concat([st.session_state.data, new_df], ignore_index=True))
                        save_data(st.session_state.data)
                        st.success(f"총 {len(new_rows)}건의 데이터가 성공적으로 등록되었습니다!")
                        del st.session_state.scraped_df
                        st.rerun()

    # -------------------------------------------------------------------
    # 탭 4: 엑셀 파일 가져오기
    # -------------------------------------------------------------------
    with tab_excel:
        st.subheader("📊 엑셀 파일에서 생활인 정보 가져오기")
        
        with st.expander("ℹ️ 사용 방법", expanded=True):
            st.markdown("""
            이 기능은 네트워크 드라이브의 **종합관리 엑셀 파일**에서 생활인 정보를 직접 가져옵니다.
            
            **장점:**
            - 희망이음 웹사이트 접속 불필요
            - 안정적인 데이터 가져오기
            - 이미 정리된 생활인 정보 활용
            
            **사용 순서:**
            1. 아래 파일 경로가 맞는지 확인
            2. "파일 미리보기" 버튼으로 데이터 확인
            3. 컬럼 매핑 설정 (이름, 병원명 등)
            4. 기본 설정 입력 (복용시간대, 복용일수)
            5. "데이터 가져오기" 실행
            """)
        
        # 파일 경로 설정
        st.markdown("### 📁 파일 경로")
        col_p1, col_p2 = st.columns([3, 1])
        with col_p1:
            excel_path = st.text_input(
                "엑셀 파일 경로",
                value=EXCEL_FILE_PATH,
                help="네트워크 드라이브 경로를 입력하세요",
                key="excel_path_input"
            )
        with col_p2:
            st.caption("기본 경로가 설정되어 있습니다")
        
        # 파일 미리보기
        col_b1, col_b2 = st.columns([1, 3])
        with col_b1:
            if st.button("🔍 파일 미리보기", use_container_width=True, key="btn_preview_excel"):
                with st.spinner("파일을 읽는 중..."):
                    df_excel, error = load_excel_from_network(excel_path)
                    if error:
                        st.error(error)
                    else:
                        st.session_state.excel_preview = df_excel
                        st.success(f"✅ 파일 읽기 성공! (총 {len(df_excel)}행)")
        
        # 미리보기 데이터 표시
        if "excel_preview" in st.session_state:
            st.markdown("---")
            st.markdown("### 📋 파일 미리보기")
            
            df_preview = st.session_state.excel_preview
            st.caption(f"총 {len(df_preview)}행 × {len(df_preview.columns)}열")
            
            # 처음 10행만 표시
            st.dataframe(df_preview.head(10), use_container_width=True)
            
            # 컬럼 매핑 및 가져오기 폼
            st.markdown("---")
            st.markdown("### ⚙️ 데이터 가져오기 설정")
            
            with st.form("excel_import_form"):
                st.markdown("#### 1️⃣ 컬럼 매핑")
                st.caption("엑셀 파일의 어떤 컬럼을 사용할지 선택하세요")
                
                all_cols = df_preview.columns.tolist()
                
                col_m1, col_m2, col_m3 = st.columns(3)
                with col_m1:
                    # 이름 컬럼 자동 감지
                    name_candidates = [c for c in all_cols if any(keyword in str(c) for keyword in ["이름", "성명", "명", "Name"])]
                    default_name_idx = all_cols.index(name_candidates[0]) if name_candidates else 0
                    col_name = st.selectbox("성명 컬럼 (필수)", options=all_cols, index=default_name_idx, key="excel_col_name")
                
                with col_m2:
                    # 병원명 컬럼 자동 감지
                    hospital_candidates = [c for c in all_cols if any(keyword in str(c) for keyword in ["병원", "의료", "진료", "Hospital"])]
                    default_hospital_idx = all_cols.index(hospital_candidates[0]) if hospital_candidates else 0
                    col_hospital = st.selectbox("병원명 컬럼 (선택)", options=["(사용안함)"] + all_cols, index=0, key="excel_col_hospital")
                
                with col_m3:
                    # 비고 컬럼 자동 감지
                    memo_candidates = [c for c in all_cols if any(keyword in str(c) for keyword in ["비고", "메모", "특이", "Memo", "Note"])]
                    default_memo_idx = all_cols.index(memo_candidates[0]) if memo_candidates else 0
                    col_memo = st.selectbox("비고 컬럼 (선택)", options=["(사용안함)"] + all_cols, index=0, key="excel_col_memo")
                
                st.markdown("#### 2️⃣ 기본값 설정")
                st.caption("가져온 데이터에 적용할 기본값을 설정하세요")
                
                col_d1, col_d2, col_d3 = st.columns(3)
                with col_d1:
                    default_time_slot = st.selectbox("기본 복용시간대", options=TIME_OPTIONS, index=0, key="excel_default_time")
                with col_d2:
                    default_days = st.number_input("기본 복용일수", min_value=1, value=30, key="excel_default_days")
                with col_d3:
                    default_drug_name = st.text_input("기본 약품명", value="(엑셀 가져오기)", help="약품명이 없을 경우 사용", key="excel_default_drug")
                
                st.markdown("#### 3️⃣ 가져오기 옵션")
                col_o1, col_o2 = st.columns(2)
                with col_o1:
                    skip_duplicates = st.checkbox("중복 이름 건너뛰기", value=True, help="이미 등록된 이름은 가져오지 않습니다", key="excel_skip_dup")
                with col_o2:
                    skip_empty = st.checkbox("빈 이름 건너뛰기", value=True, help="이름이 비어있는 행은 가져오지 않습니다", key="excel_skip_empty")
                
                import_submit = st.form_submit_button("🚀 데이터 가져오기", use_container_width=True, type="primary")
                
                if import_submit:
                    # 데이터 가져오기 처리
                    new_rows = []
                    skipped_count = 0
                    existing_names = set(st.session_state.data["이름"].dropna().unique()) if not st.session_state.data.empty else set()
                    
                    for idx, row in df_preview.iterrows():
                        # 이름 추출
                        name = str(row[col_name]).strip() if pd.notna(row[col_name]) else ""
                        
                        # 빈 이름 건너뛰기
                        if skip_empty and not name:
                            skipped_count += 1
                            continue
                        
                        # 중복 건너뛰기
                        if skip_duplicates and name in existing_names:
                            skipped_count += 1
                            continue
                        
                        # 병원명 추출
                        if col_hospital != "(사용안함)":
                            hospital = str(row[col_hospital]).strip() if pd.notna(row[col_hospital]) else ""
                        else:
                            hospital = "(엑셀 가져오기)"
                        
                        # 비고 추출
                        if col_memo != "(사용안함)":
                            memo = str(row[col_memo]).strip() if pd.notna(row[col_memo]) else ""
                        else:
                            memo = "엑셀 파일에서 가져옴"
                        
                        # 처방일은 오늘로 설정
                        start_date = pd.to_datetime(date.today())
                        end_date = start_date + timedelta(days=int(default_days))
                        
                        new_rows.append({
                            "기록ID": generate_id(),
                            "이름": name,
                            "병원명": hospital if hospital else "(미지정)",
                            "약품명": default_drug_name,
                            "복용시간대": default_time_slot,
                            "처방일": start_date,
                            "복용일수": int(default_days),
                            "종료예정일": end_date,
                            "비고": memo,
                            "남은약": 0
                        })
                        
                        # 중복 체크용 세트에 추가
                        existing_names.add(name)
                    
                    if new_rows:
                        new_df = pd.DataFrame(new_rows)
                        st.session_state.data = ensure_schema(pd.concat([st.session_state.data, new_df], ignore_index=True))
                        save_data(st.session_state.data)
                        
                        st.success(f"✅ 총 {len(new_rows)}건의 데이터를 성공적으로 가져왔습니다!")
                        if skipped_count > 0:
                            st.info(f"ℹ️ {skipped_count}건은 중복 또는 빈 이름으로 건너뛰었습니다.")
                        
                        # 미리보기 데이터 삭제
                        del st.session_state.excel_preview
                        st.rerun()
                    else:
                        st.warning("⚠️ 가져올 데이터가 없습니다. 설정을 확인해주세요.")
                        if skipped_count > 0:
                            st.info(f"ℹ️ 총 {skipped_count}건이 중복 또는 빈 이름으로 건너뛰어졌습니다.")

    # -------------------------------------------------------------------
    # 탭 5: 삭제 (현재 필터 결과 기준) — 전체 선택/해제 + 선택 유지
    # -------------------------------------------------------------------
    with tab_del:
        st.subheader("🗑️ 삭제 도구")

        if filtered_sorted.empty:
            st.info("삭제할 대상이 없습니다. (검색 조건을 확인해 주세요)")
        else:
            # 삭제 에디터용 데이터프레임: 현재 필터 결과만
            delete_df = filtered_sorted.copy()  # ['기록ID' + 표시 컬럼]
            delete_df = delete_df.rename(columns={
                "처방일": "처방일(표시용)",
                "종료예정일": "종료예정일(표시용)"
            })
            delete_df["처방일(표시용)"] = pd.to_datetime(delete_df["처방일(표시용)"], errors="coerce").dt.date
            delete_df["종료예정일(표시용)"] = pd.to_datetime(delete_df["종료예정일(표시용)"], errors="coerce").dt.date

            # ✅ 세션에 저장된 선택 상태로 '삭제' 체크 채워넣기
            sel_set = set(st.session_state.delete_selected_ids)
            delete_df.insert(1, "삭제", delete_df["기록ID"].isin(sel_set))

            # 상단 컨트롤: 전체 선택/해제 버튼 (세션에 직접 반영)
            bc1, bc2, bc3 = st.columns([1, 1, 3])
            with bc1:
                if st.button("✅ 전체 선택", use_container_width=True, key="btn_select_all"):
                    st.session_state.delete_selected_ids = delete_df["기록ID"].tolist()
                    st.rerun()
            with bc2:
                if st.button("↩️ 전체 해제", use_container_width=True, key="btn_clear_all"):
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
                disabled=[
                    "기록ID", "이름", "병원명", "약품명", "복용시간대",
                    "처방일(표시용)", "종료예정일(표시용)", "복용일수", "남은일수", "비고", "남은약"
                ],
                use_container_width=True,
                key="delete_editor",
                hide_index=True
            )

            # ✅ 사용자가 체크/해제한 최신 상태를 세션에 반영
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
                confirm = st.checkbox("정말 삭제하시겠습니까?", value=False, key="chk_confirm_delete")
            with col_d2:
                run_delete = st.button("🚨 선택 행 삭제", type="primary", use_container_width=True, key="btn_run_delete")

            # 복원(Undo)
            col_u1, col_u2 = st.columns([1, 1])
            with col_u1:
                can_undo = len(st.session_state.undo_stack) > 0
                if st.button("↩️ 마지막 삭제 복원", disabled=not can_undo, use_container_width=True, key="btn_undo"):
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
        unique_names = filtered_df["이름"].dropna().unique().tolist() if not filtered_df.empty else []
        if len(unique_names) == 1 and not filtered_df.empty:
            with st.expander(f"🧹 '{unique_names[0]}' 대상자 기록 일괄 삭제 (주의)", expanded=False):
                st.warning("이 기능은 현재 필터 결과에서 해당 대상자의 모든 기록을 삭제합니다. 신중히 사용하세요.")
                all_confirm = st.checkbox("정말 이 대상자의 모든 기록을 삭제합니다.", value=False, key="chk_all_delete")
                all_delete = st.button("🚨 이 대상자 기록 전체 삭제", key="btn_all_delete")
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

# -------------------------------
# (D) 상위 폴더의 xlsx 파일 읽기 및 데이터 추가
# -------------------------------

def append_to_excel(file_path: str, new_data: pd.DataFrame):
    """
    상위 폴더에 있는 xlsx 파일을 읽고 데이터를 추가한 후 저장합니다.
    """
    try:
        if os.path.exists(file_path):
            # 기존 데이터 읽기
            existing_data = pd.read_excel(file_path)
            # 새로운 데이터 추가
            updated_data = pd.concat([existing_data, new_data], ignore_index=True)
        else:
            # 파일이 없으면 새로운 데이터로 생성
            updated_data = new_data

        # 데이터 저장
        updated_data.to_excel(file_path, index=False)
        st.success("데이터가 성공적으로 추가되었습니다.")
    except Exception as e:
        st.error(f"데이터를 추가하는 중 오류가 발생했습니다: {e}")

# -------------------------------
# (E) 데이터 추가 UI
# -------------------------------

if data_source == "로컬 파일":
    if st.button("데이터 추가 및 저장"):
        new_data = st.experimental_data_editor(data, num_rows="dynamic")
        append_to_excel(local_file_path, new_data)

# -------------------------------
# (F) 네트워크 폴더 연결 및 파일 읽기/쓰기
# -------------------------------

def connect_to_network_folder(network_path: str, username: str, password: str):
    """
    네트워크 폴더에 연결합니다.
    """
    try:
        command = f'net use {network_path} /user:{username} {password}'
        os.system(command)
        st.success("네트워크 폴더에 성공적으로 연결되었습니다.")
    except Exception as e:
        st.error(f"네트워크 폴더 연결 중 오류가 발생했습니다: {e}")

def read_network_file(file_path: str) -> pd.DataFrame:
    """
    네트워크 폴더에서 파일을 읽습니다.
    """
    try:
        if os.path.exists(file_path):
            return pd.read_excel(file_path)
        else:
            st.error(f"지정된 파일을 찾을 수 없습니다: {file_path}")
            return pd.DataFrame(columns=REQUIRED_COLS)
    except Exception as e:
        st.error(f"네트워크 파일을 읽는 중 오류가 발생했습니다: {e}")
        return pd.DataFrame(columns=REQUIRED_COLS)

def save_to_network_file(df: pd.DataFrame, file_path: str):
    """
    네트워크 폴더의 파일에 데이터를 저장합니다.
    """
    try:
        df.to_excel(file_path, index=False)
        st.success("데이터가 네트워크 파일에 저장되었습니다.")
    except Exception as e:
        st.error(f"네트워크 파일에 데이터를 저장하는 중 오류가 발생했습니다: {e}")

# -------------------------------
# (G) 네트워크 폴더 연결 및 데이터 처리 UI
# -------------------------------

if data_source == "로컬 파일":
    local_file_path = st.text_input("로컬 파일 경로를 입력하세요", EXCEL_FILE_PATH, key="local_file_path")
    if st.button("로컬 데이터 로드"):
        data = load_local_data(local_file_path)
    if st.button("로컬 데이터 저장"):
        save_local_data(data, local_file_path)

elif data_source == "Microsoft Lists/OneDrive":
    data = pd.read_csv(DB_FILE)  # 기존 로직 유지

else:  # 네트워크 폴더
    network_path = st.text_input("네트워크 폴더 경로를 입력하세요", r"\\ep_nas1\만성요양과", key="network_path")
    username = st.text_input("사용자 이름을 입력하세요", key="username")
    password = st.text_input("비밀번호를 입력하세요", type="password", key="password")
    network_file_path = st.text_input("네트워크 파일 경로를 입력하세요", EXCEL_FILE_PATH, key="network_file_path")

    if st.button("네트워크 폴더 연결"):
        connect_to_network_folder(network_path, username, password)

    if st.button("네트워크 데이터 로드"):
        data = read_network_file(network_file_path)

    if st.button("네트워크 데이터 저장"):
        save_to_network_file(data, network_file_path)

# -------------------------------
# (H) 네트워크 파일 서식 변환 및 저장
# -------------------------------

def transform_to_list_format(df: pd.DataFrame) -> pd.DataFrame:
    """
    네트워크에서 읽은 데이터를 Microsoft Lists에 맞는 형식으로 변환합니다.
    """
    try:
        # 예시: 필요한 열만 선택하고 이름 변경
        transformed_df = df[["이름", "병원명", "약품명", "처방일", "복용일수"]].copy()
        transformed_df.rename(columns={
            "이름": "Name",
            "병원명": "Hospital",
            "약품명": "Medication",
            "처방일": "Prescription Date",
            "복용일수": "Days of Use"
        }, inplace=True)
        return transformed_df
    except KeyError as e:
        st.error(f"필요한 열이 누락되었습니다: {e}")
        return pd.DataFrame()

def save_transformed_file(df: pd.DataFrame, save_path: str):
    """
    변환된 데이터를 새로운 xlsx 파일로 저장합니다.
    """
    try:
        df.to_excel(save_path, index=False)
        st.success(f"변환된 파일이 저장되었습니다: {save_path}")
    except Exception as e:
        st.error(f"파일 저장 중 오류가 발생했습니다: {e}")

# -------------------------------
# (I) 서식 변환 UI
# -------------------------------

if data_source == "네트워크 파일":
    if st.button("네트워크 파일 서식 변환 및 저장"):
        network_file_path = st.text_input("네트워크 파일 경로를 입력하세요", EXCEL_FILE_PATH)
        transformed_save_path = st.text_input("변환된 파일 저장 경로를 입력하세요", "transformed_file.xlsx")

        if os.path.exists(network_file_path):
            original_data = read_network_file(network_file_path)
            transformed_data = transform_to_list_format(original_data)

            if not transformed_data.empty:
                save_transformed_file(transformed_data, transformed_save_path)
        else:
            st.error("네트워크 파일 경로가 올바르지 않습니다.")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        # Streamlit 내부 예외(Rerun, Stop)는 그대로 통과시켜야 함
        if type(e).__name__ in ["RerunException", "StopException"]:
            raise e
        st.error(f"⚠️ 앱 실행 중 상세 오류가 발생했습니다: {e}")
        st.exception(e)
