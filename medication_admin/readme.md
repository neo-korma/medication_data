
# 💊 복지시설 투약 관리 (Microsoft Lists + OneDrive)

모바일 대응 탭 UI 기반의 Streamlit 앱입니다.  
데이터는 **Microsoft Lists(SharePoint)** 에 저장하고, **OneDrive**에 CSV 백업을 유지합니다.  
오프라인/장애 대비를 위해 **로컬 CSV 캐시**도 함께 사용합니다.

---

## 🧩 주요 기능
- 단일 비밀번호 게이트 (PBKDF2 해시)
- 투약 정보 등록/검색/삭제 (모바일 친화 UI)
- 대시보드(개인 요약/전체 표)
- **저장/로드 우선순위**
  1) 로컬 CSV → 2) Microsoft List → 3) OneDrive 백업 CSV
- 저장 시: 로컬 CSV + Microsoft List(전체 동기화) + OneDrive 백업 업로드

---

## 🛠️ 사전 준비

### 1) Python 버전
- Python **3.10 ~ 3.12** 권장

### 2) 패키지 설치
```bash
pip install -r requirements.txt
``