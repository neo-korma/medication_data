
# 복지시설 투약 관리 – 배포 가이드

## 1) 폴더 구조
.
├─ app.py                     # 앱 본문 (이미 있음)
├─ requirements.txt           # 의존성 (필수)
├─ .gitignore                 # git 제외 파일
└─ .streamlit/
   └─ secrets.toml            # (로컬 테스트용) 배포 시 Cloud UI에 붙여넣기

## 2) GitHub 업로드
1) GitHub에 새 Repository 생성 (Public 권장)
2) 위 파일들을 포함해 push

## 3) Streamlit Community Cloud 무료 배포
1) https://streamlit.io/cloud 접속 후 GitHub 계정으로 로그인
2) **“New app” → 리포지토리/브랜치 선택 → main file = app.py** 지정 → Deploy  
   배포가 완료되면 `https://<app-name>-<owner>.streamlit.app` 형태의 URL이 발급됩니다.
3) 좌측 상단 ••• → **“Edit secrets”** 메뉴에 로컬의 `.streamlit/secrets.toml` 내용을 붙여넣고 **Save**  
   (secrets는 코드에 커밋하지 않습니다)

> 참고 문서:  
> - Streamlit Community Cloud 소개/배포: https://streamlit.io/cloud  
> - 공식 배포/관리 가이드: https://docs.streamlit.io/deploy/streamlit-community-cloud  
> - Cloud에서 Secrets 설정: https://docs.streamlit.io/develop/tutorials/authentication/microsoft (섹션: Deploy your app on Community Cloud)

## 4) Microsoft Teams에 공유
### (가장 간단) 웹사이트 탭으로 추가
- Teams 채널 상단 **“+”** → **Website(웹사이트)** 선택 → 위에서 발급받은 앱 URL 붙여넣기 → 저장  
- 2024-07 이후 정책상 웹사이트 탭은 **Teams 내 탭이 아닌 브라우저 새 탭으로 열릴 수 있음** (보안정책 변경)  
  - 변경 사항 안내:  
    - https://teams.handsontek.net/2024/07/09/add-website-tab-microsoft-teams-post-july-2024/  
    - https://learn.microsoft.com/en-us/answers/questions/5367146/in-ms-teams-how-do-i-set-a-website-app-tab-to-open

### (대안) SharePoint News Link 경유로 탭 내 표시 시도
- 팀과 연결된 SharePoint 사이트에서 **News Link**로 외부 URL 등록 → Teams에서 **SharePoint 페이지**를 탭으로 추가  
- 일부 환경에서 탭 내 표시가 가능 (문서/가이드 참조):  
  - https://teams.handsontek.net/2024/07/09/add-website-tab-microsoft-teams-post-july-2024/

> Teams에서 웹사이트 탭 추가 방법 일반 가이드:  
> https://td.usnh.edu/TDClient/60/Portal/KB/ArticleDet?ID=3098

## 5) 모바일 동작
- Teams 모바일은 탭을 브라우저로 열거나 인앱 웹뷰로 띄울 수 있음.  
- 기본 동작/주의사항은 Microsoft 문서 참고:  
  - https://learn.microsoft.com/en-us/microsoftteams/platform/tabs/design/tabs-mobile
``
