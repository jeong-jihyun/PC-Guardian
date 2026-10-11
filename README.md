# PC-Guardian

개인 윈도우 PC를 위한 보호 프로그램입니다. 특정 공격을 가정하지 않고 **"평소 지켜보기 → 이상 감지 → 되돌리기"** 구조로 동작하며, 외부(다른 컴퓨터)를 공격하거나 추적하지 않습니다 — 오직 사용자 자신의 PC를 지키는 용도입니다.

## 구성

이 저장소는 같은 프로그램의 두 가지 구현을 담고 있습니다.

| 폴더 | 내용 | 실행 방식 |
|---|---|---|
| [`cpp/`](./cpp) | 순수 C++ (Win32 API) 네이티브 버전 — 권장 | 빌드된 `.exe`를 더블클릭 |
| [`powershell/`](./powershell) | PowerShell + WPF GUI 버전 | PowerShell 스크립트 실행 |

### 왜 두 버전이 있는가

PowerShell 버전을 먼저 만들었는데, 실행할 때마다 PowerShell 콘솔을 열고 실행 정책을 설정해야 하는 불편함이 있었습니다. 그래서 외부 의존성 없이 더블클릭만으로 실행되는 **C++ 네이티브 버전**을 다시 만들었고, 이쪽이 현재 권장 버전입니다. PowerShell 버전은 참고/비교용으로 남겨둡니다.

## 주요 기능

- **실시간 감시**: 프로세스·시작프로그램·블루투스 기기 변화 감지
- **침입 차단**: RDP 로그인 실패 자동 차단(fail2ban 방식), 수동 IP/대역 차단
- **파일 무결성 검사**: SHA-256 해시 비교로 파일 변조·삭제 탐지
- **복구/백업**: 시스템 복원 지점 생성 및 복구
- **격리함**: 의심 프로세스 종료, 의심 파일 격리
- **검사**: Windows Defender 연동 + 자체 엔진(해시 블랙리스트/패턴 시그니처/휴리스틱) + abuse.ch MalwareBazaar 실시간 위협 인텔리전스 연동
- **증거/신고**: 스크린샷·로그 수집, KISA·경찰 사이버수사국 신고용 리포트 자동 생성

## 빌드 방법 (C++ 버전)

Windows에 Visual Studio가 있다면 `cpp/PCGuardian.cpp`를 그대로 컴파일할 수 있고, Linux에서 mingw-w64로 크로스 컴파일할 수도 있습니다.

```bash
# Linux에서 크로스 컴파일 (mingw-w64 필요: apt install mingw-w64 g++-mingw-w64-x86-64)
x86_64-w64-mingw32-g++ -std=c++17 -municode -mwindows cpp/PCGuardian.cpp -o PC-Guardian.exe \
  -lcomctl32 -lcomdlg32 -lshell32 -liphlpapi -lwbemuuid -lole32 -loleaut32 -lsrclient \
  -lbluetoothapis -lgdi32 -ladvapi32 -lcrypt32 -lwintrust -lwinhttp
```

자세한 사용법은 각 폴더의 `*_사용법.md` 문서를 참고하세요.

## 주의사항

- `검사` 기능의 자체 엔진은 완전한 상용 백신을 대체하지 않습니다. 해시 블랙리스트는 기본적으로 비어 있으며, abuse.ch MalwareBazaar의 무료 Auth-Key를 등록하면 실시간 공개 위협정보로 채울 수 있습니다.
- 방화벽 차단, 복원 지점 생성/복구 등 일부 기능은 **관리자 권한 실행**이 필요합니다.
- 이 프로그램은 자신의 PC를 보호하는 용도로만 설계되었습니다.
