// ================================================================
// PC-Guardian.cpp
// 개인 PC 보호 프로그램 - 순수 C++ (Win32 API) 네이티브 버전
// PowerShell을 전혀 사용하지 않습니다. 윈도우 자체 API만으로 동작합니다.
// ================================================================

#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601
#define UNICODE
#define _UNICODE

#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <shlobj.h>
#include <tlhelp32.h>
#include <iphlpapi.h>
#include <wincrypt.h>
#include <bluetoothapis.h>
#include <shellapi.h>
#include <wintrust.h>
#include <softpub.h>
#include <winhttp.h>
#include <srrestoreptapi.h>
#include <wbemidl.h>
#include <comdef.h>
#include <string>
#include <vector>
#include <map>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cstdio>
#include <cwctype>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "srclient.lib")
#pragma comment(lib, "bluetoothapis.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "winhttp.lib")

using namespace std;

// ================================================================
// 전역 경로 / 상태
// ================================================================
wstring g_baseDir, g_logDir, g_snapDir, g_evidenceDir, g_stateDir, g_quarantineDir;

struct BlockedIP { wstring ip, time, reason; };
struct QuarantineItem { wstring time, type, target; };

vector<BlockedIP> g_blockedIPs;
vector<QuarantineItem> g_quarantineItems;
vector<wstring> g_watchedFolders;
map<wstring, wstring> g_fileBaseline;

vector<wstring> g_watchBaseline_proc, g_watchBaseline_startup, g_watchBaseline_bt;
vector<DWORD>   g_procListPids; // 프로세스 목록박스와 같은 순서로 PID 저장

// ---- 자체 검사 엔진 ----
vector<wstring> g_hashBlacklist;   // 악성파일 해시 블랙리스트 (SHA-256, 소문자)
vector<string>  g_patternList;     // 파일 내용에서 찾을 의심 문자열 패턴 (ASCII)
vector<wstring> g_scanResultPaths; // 검사 결과 목록과 같은 순서로 전체 경로 저장
volatile bool g_scanRunning = false;
volatile bool g_scanCancel = false;
HWND g_lblScanProgress = NULL;
HWND g_edtScanRoot = NULL;
HWND g_edtMbKey = NULL;
wstring g_mbApiKey;

HWND g_hMain;
HWND g_panels[9];
HWND g_lblSnap, g_lblWatch, g_lblBlocked, g_lblQuar;
HWND g_lstDashRecent, g_lstWatch, g_lstBlocked, g_lstFolders, g_lstFileResult;
HWND g_lstRestore, g_lstProc, g_lstQuarHist, g_lstEvidence, g_lstLog, g_lstScan;
HWND g_edtWatchInterval, g_edtFwThreshold, g_edtManualIP;

enum {
    ID_NAV_DASH = 1000, ID_NAV_WATCH, ID_NAV_FW, ID_NAV_FILE, ID_NAV_RESTORE, ID_NAV_QUAR, ID_NAV_EVID, ID_NAV_LOG, ID_NAV_SCAN,
    ID_DASH_SNAP, ID_DASH_PROTECT,
    ID_WATCH_START, ID_WATCH_STOP,
    ID_FW_START, ID_FW_STOP, ID_FW_BLOCK, ID_FW_IMPORT, ID_FW_UNBLOCK,
    ID_FILE_ADDFOLDER, ID_FILE_BASELINE, ID_FILE_CHECK,
    ID_RESTORE_CREATE, ID_RESTORE_REFRESH, ID_RESTORE_DO,
    ID_QUAR_REFRESH, ID_QUAR_KILL,
    ID_EVID_SCREENSHOT, ID_EVID_COLLECT, ID_EVID_REPORT,
    ID_LOG_REFRESH, ID_LOG_OPENFOLDER,
    ID_SCAN_DEFENDER_QUICK, ID_SCAN_DEFENDER_FULL,
    ID_SCAN_START, ID_SCAN_STOP, ID_SCAN_QUARANTINE, ID_SCAN_IMPORT_HASH, ID_SCAN_IMPORT_PATTERN, ID_SCAN_UPDATE_FEED,
    ID_TIMER_WATCH = 500, ID_TIMER_FW = 501,
    WM_SCAN_DONE = WM_APP + 1
};

// ================================================================
// 문자열 / 시간 유틸
// ================================================================
string WToU8(const wstring& w) {
    if (w.empty()) return string();
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), NULL, 0, NULL, NULL);
    string out(n, 0);
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &out[0], n, NULL, NULL);
    return out;
}
wstring NowDateStamp() {
    SYSTEMTIME st; GetLocalTime(&st);
    wchar_t buf[32]; swprintf(buf, 32, L"%04d%02d%02d", st.wYear, st.wMonth, st.wDay);
    return wstring(buf);
}
wstring NowTimeStamp() {
    SYSTEMTIME st; GetLocalTime(&st);
    wchar_t buf[32]; swprintf(buf, 32, L"%04d%02d%02d_%02d%02d%02d", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return wstring(buf);
}
wstring NowReadable() {
    SYSTEMTIME st; GetLocalTime(&st);
    wchar_t buf[32]; swprintf(buf, 32, L"%04d-%02d-%02d %02d:%02d:%02d", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return wstring(buf);
}

void WriteLog(const wstring& msg, const wstring& level = L"정보") {
    wstring path = g_logDir + L"\\guardian_" + NowDateStamp() + L".log";
    wstring line = L"[" + NowReadable() + L"] [" + level + L"] " + msg + L"\r\n";
    string utf8 = WToU8(line);
    HANDLE h = CreateFileW(path.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD written; WriteFile(h, utf8.c_str(), (DWORD)utf8.size(), &written, NULL);
        CloseHandle(h);
    }
}

void EnsureDir(const wstring& path) { CreateDirectoryW(path.c_str(), NULL); }

// 외부 명령 실행 (콘솔창 숨김) - 출력 캡처 없이 성공여부만
bool RunHidden(const wstring& command) {
    wstring full = L"cmd.exe /c " + command;
    vector<wchar_t> buf(full.begin(), full.end()); buf.push_back(0);
    STARTUPINFOW si{}; si.cb = sizeof(si); si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi{};
    BOOL ok = CreateProcessW(NULL, buf.data(), NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    if (!ok) return false;
    WaitForSingleObject(pi.hProcess, 15000);
    DWORD code = 1; GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    return code == 0;
}

// 외부 명령 실행 + 표준출력 캡처
wstring RunCapture(const wstring& command) {
    SECURITY_ATTRIBUTES sa{ sizeof(sa), NULL, TRUE };
    HANDLE hRead, hWrite;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) return L"";
    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

    wstring full = L"cmd.exe /c " + command;
    vector<wchar_t> buf(full.begin(), full.end()); buf.push_back(0);
    STARTUPINFOW si{}; si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdOutput = hWrite; si.hStdError = hWrite; si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi{};
    BOOL ok = CreateProcessW(NULL, buf.data(), NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    CloseHandle(hWrite);
    string result;
    if (ok) {
        char chunk[4096]; DWORD n;
        while (ReadFile(hRead, chunk, sizeof(chunk), &n, NULL) && n > 0) result.append(chunk, n);
        WaitForSingleObject(pi.hProcess, 15000);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    }
    CloseHandle(hRead);
    int wlen = MultiByteToWideChar(CP_OEMCP, 0, result.c_str(), (int)result.size(), NULL, 0);
    wstring wres(wlen, 0);
    if (wlen > 0) MultiByteToWideChar(CP_OEMCP, 0, result.c_str(), (int)result.size(), &wres[0], wlen);
    return wres;
}

// ================================================================
// 상태 저장/불러오기 (간단한 텍스트 포맷)
// ================================================================
void SaveState() {
    {
        wofstream f((g_stateDir + L"\\blocked.txt").c_str());
        for (auto& b : g_blockedIPs) f << b.ip << L"|" << b.time << L"|" << b.reason << L"\n";
    }
    {
        wofstream f((g_stateDir + L"\\quarantine.txt").c_str());
        for (auto& q : g_quarantineItems) f << q.time << L"|" << q.type << L"|" << q.target << L"\n";
    }
    {
        wofstream f((g_stateDir + L"\\folders.txt").c_str());
        for (auto& p : g_watchedFolders) f << p << L"\n";
    }
    {
        wofstream f((g_stateDir + L"\\baseline.txt").c_str());
        for (auto& kv : g_fileBaseline) f << kv.first << L"|" << kv.second << L"\n";
    }
}
vector<wstring> SplitPipe(const wstring& line) {
    vector<wstring> parts; wstringstream ss(line); wstring item;
    while (getline(ss, item, L'|')) parts.push_back(item);
    return parts;
}
void LoadState() {
    {
        wifstream f((g_stateDir + L"\\blocked.txt").c_str()); wstring line;
        while (getline(f, line)) { auto p = SplitPipe(line); if (p.size() >= 3) g_blockedIPs.push_back({ p[0], p[1], p[2] }); }
    }
    {
        wifstream f((g_stateDir + L"\\quarantine.txt").c_str()); wstring line;
        while (getline(f, line)) { auto p = SplitPipe(line); if (p.size() >= 3) g_quarantineItems.push_back({ p[0], p[1], p[2] }); }
    }
    {
        wifstream f((g_stateDir + L"\\folders.txt").c_str()); wstring line;
        while (getline(f, line)) if (!line.empty()) g_watchedFolders.push_back(line);
    }
    {
        wifstream f((g_stateDir + L"\\baseline.txt").c_str()); wstring line;
        while (getline(f, line)) { auto p = SplitPipe(line); if (p.size() >= 2) g_fileBaseline[p[0]] = p[1]; }
    }
    {
        wifstream f((g_stateDir + L"\\mbkey.txt").c_str()); wstring line;
        if (getline(f, line)) g_mbApiKey = line;
    }
}

// ================================================================
// 시스템 스냅샷 (프로세스 / 시작프로그램 / 블루투스)
// ================================================================
vector<wstring> GetProcessList() {
    vector<wstring> list;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return list;
    PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do { list.push_back(pe.szExeFile); } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return list;
}
void EnumRunKey(HKEY root, const wchar_t* subkey, vector<wstring>& out) {
    HKEY hKey;
    if (RegOpenKeyExW(root, subkey, 0, KEY_READ, &hKey) != ERROR_SUCCESS) return;
    wchar_t name[256]; DWORD idx = 0, nameLen;
    while (true) {
        nameLen = 256;
        if (RegEnumValueW(hKey, idx, name, &nameLen, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;
        out.push_back(name);
        idx++;
    }
    RegCloseKey(hKey);
}
vector<wstring> GetStartupList() {
    vector<wstring> list;
    EnumRunKey(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", list);
    EnumRunKey(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", list);
    return list;
}
vector<wstring> GetBluetoothList() {
    vector<wstring> list;
    BLUETOOTH_DEVICE_SEARCH_PARAMS params{};
    params.dwSize = sizeof(params);
    params.fReturnAuthenticated = TRUE;
    params.fReturnRemembered = TRUE;
    params.fReturnUnknown = TRUE;
    params.fReturnConnected = TRUE;
    params.fIssueInquiry = FALSE;
    params.cTimeoutMultiplier = 0;
    BLUETOOTH_DEVICE_INFO info{}; info.dwSize = sizeof(info);
    HBLUETOOTH_DEVICE_FIND hFind = BluetoothFindFirstDevice(&params, &info);
    if (hFind) {
        do { list.push_back(info.szName); } while (BluetoothFindNextDevice(hFind, &info));
        BluetoothFindDeviceClose(hFind);
    }
    return list;
}
vector<wstring> DiffNew(const vector<wstring>& oldList, const vector<wstring>& newList) {
    vector<wstring> diffs;
    for (auto& n : newList) {
        if (find(oldList.begin(), oldList.end(), n) == oldList.end()) diffs.push_back(n);
    }
    return diffs;
}

// ================================================================
// 파일 해시 (SHA-256) / 폴더 재귀 열거
// ================================================================
wstring Sha256File(const wstring& path) {
    HCRYPTPROV hProv = 0; HCRYPTHASH hHash = 0;
    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return L"";
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) { CryptReleaseContext(hProv, 0); return L""; }
    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) { CryptDestroyHash(hHash); CryptReleaseContext(hProv, 0); return L""; }
    BYTE buf[8192]; DWORD n;
    while (ReadFile(hFile, buf, sizeof(buf), &n, NULL) && n > 0) CryptHashData(hHash, buf, n, 0);
    CloseHandle(hFile);
    BYTE hash[32]; DWORD hashLen = 32;
    wstring result;
    if (CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) {
        wchar_t hex[65];
        for (int i = 0; i < 32; i++) swprintf(hex + i * 2, 3, L"%02x", hash[i]);
        hex[64] = 0;
        result = hex;
    }
    CryptDestroyHash(hHash); CryptReleaseContext(hProv, 0);
    return result;
}
void EnumFilesRecursive(const wstring& folder, vector<wstring>& out) {
    WIN32_FIND_DATAW fd;
    wstring pattern = folder + L"\\*";
    HANDLE h = FindFirstFileW(pattern.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        wstring name = fd.cFileName;
        if (name == L"." || name == L"..") continue;
        wstring full = folder + L"\\" + name;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) EnumFilesRecursive(full, out);
        else out.push_back(full);
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

// ================================================================
// 방화벽 IP 차단 (netsh 기반)
// ================================================================
bool BlockIP(const wstring& ip, const wstring& reason) {
    for (auto& b : g_blockedIPs) if (b.ip == ip) return false;
    wstring cmdIn = L"netsh advfirewall firewall add rule name=\"PCGuardian-Block-" + ip + L"\" dir=in action=block remoteip=" + ip;
    wstring cmdOut = L"netsh advfirewall firewall add rule name=\"PCGuardian-Block-" + ip + L"-Out\" dir=out action=block remoteip=" + ip;
    bool ok = RunHidden(cmdIn);
    RunHidden(cmdOut);
    if (ok) {
        g_blockedIPs.push_back({ ip, NowReadable(), reason });
        SaveState();
        WriteLog(L"IP 차단: " + ip + L" (" + reason + L")", L"경고");
    } else {
        WriteLog(L"IP 차단 실패: " + ip, L"오류");
    }
    return ok;
}
void UnblockIP(const wstring& ip) {
    RunHidden(L"netsh advfirewall firewall delete rule name=\"PCGuardian-Block-" + ip + L"\"");
    RunHidden(L"netsh advfirewall firewall delete rule name=\"PCGuardian-Block-" + ip + L"-Out\"");
    g_blockedIPs.erase(remove_if(g_blockedIPs.begin(), g_blockedIPs.end(),
        [&](const BlockedIP& b) { return b.ip == ip; }), g_blockedIPs.end());
    SaveState();
    WriteLog(L"IP 차단 해제: " + ip);
}

// RDP 로그인 실패(4625) 이벤트에서 IP별 횟수 집계 후 임계값 초과 시 자동 차단
void CheckFailedLogons(int thresholdCount) {
    wstring q = L"wevtutil qe Security /q:\"*[System[(EventID=4625) and TimeCreated[timediff(@SystemTime) <= 600000]]]\" /f:text /rd:true /c:300";
    wstring out = RunCapture(q);
    map<wstring, int> counts;
    wstringstream ss(out); wstring line;
    const wstring marker = L"Source Network Address:";
    while (getline(ss, line)) {
        size_t pos = line.find(marker);
        if (pos != wstring::npos) {
            wstring ip = line.substr(pos + marker.size());
            // 공백 제거
            size_t s = ip.find_first_not_of(L" \t\r\n");
            size_t e = ip.find_last_not_of(L" \t\r\n");
            if (s == wstring::npos) continue;
            ip = ip.substr(s, e - s + 1);
            if (!ip.empty() && ip != L"-") counts[ip]++;
        }
    }
    for (auto& kv : counts) {
        if (kv.second >= thresholdCount) {
            BlockIP(kv.first, L"RDP 로그인 실패 " + to_wstring(kv.second) + L"회");
        }
    }
}

// ================================================================
// 시스템 복원 지점 (생성: SRClient API / 조회+복원: WMI)
// ================================================================
bool CreateRestorePoint(const wstring& description) {
    RESTOREPOINTINFOW rpi{};
    rpi.dwEventType = BEGIN_SYSTEM_CHANGE;
    rpi.dwRestorePtType = APPLICATION_INSTALL;
    rpi.llSequenceNumber = 0;
    wcsncpy(rpi.szDescription, description.c_str(), MAX_DESC_W - 1);
    STATEMGRSTATUS status{};
    if (!SRSetRestorePointW(&rpi, &status)) return false;

    RESTOREPOINTINFOW rpiEnd = rpi;
    rpiEnd.dwEventType = END_SYSTEM_CHANGE;
    rpiEnd.llSequenceNumber = status.llSequenceNumber;
    STATEMGRSTATUS status2{};
    SRSetRestorePointW(&rpiEnd, &status2);
    return true;
}

struct RestorePointEntry { long seq; wstring desc, created; };

vector<RestorePointEntry> ListRestorePoints() {
    vector<RestorePointEntry> list;
    HRESULT hr = CoInitializeEx(0, COINIT_MULTITHREADED);
    bool needUninit = SUCCEEDED(hr);
    IWbemLocator* pLoc = NULL;
    if (SUCCEEDED(CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc))) {
        IWbemServices* pSvc = NULL;
        if (SUCCEEDED(pLoc->ConnectServer(_bstr_t(L"ROOT\\DEFAULT"), NULL, NULL, 0, 0, 0, 0, &pSvc))) {
            CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
                RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
            IEnumWbemClassObject* pEnum = NULL;
            if (SUCCEEDED(pSvc->ExecQuery(_bstr_t(L"WQL"), _bstr_t(L"SELECT * FROM SystemRestore"),
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnum))) {
                IWbemClassObject* pObj = NULL; ULONG ret = 0;
                while (pEnum->Next(WBEM_INFINITE, 1, &pObj, &ret) == S_OK) {
                    VARIANT vSeq, vDesc, vTime;
                    pObj->Get(L"SequenceNumber", 0, &vSeq, 0, 0);
                    pObj->Get(L"Description", 0, &vDesc, 0, 0);
                    pObj->Get(L"CreationTime", 0, &vTime, 0, 0);
                    RestorePointEntry e;
                    e.seq = vSeq.lVal;
                    e.desc = vDesc.bstrVal ? vDesc.bstrVal : L"";
                    e.created = vTime.bstrVal ? vTime.bstrVal : L"";
                    list.push_back(e);
                    VariantClear(&vSeq); VariantClear(&vDesc); VariantClear(&vTime);
                    pObj->Release();
                }
                pEnum->Release();
            }
            pSvc->Release();
        }
        pLoc->Release();
    }
    if (needUninit) CoUninitialize();
    return list;
}

bool RestoreToPoint(long seq) {
    bool success = false;
    HRESULT hr = CoInitializeEx(0, COINIT_MULTITHREADED);
    bool needUninit = SUCCEEDED(hr);
    IWbemLocator* pLoc = NULL;
    if (SUCCEEDED(CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc))) {
        IWbemServices* pSvc = NULL;
        if (SUCCEEDED(pLoc->ConnectServer(_bstr_t(L"ROOT\\DEFAULT"), NULL, NULL, 0, 0, 0, 0, &pSvc))) {
            CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
                RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
            IWbemClassObject* pClass = NULL;
            if (SUCCEEDED(pSvc->GetObject(_bstr_t(L"SystemRestore"), 0, NULL, &pClass, NULL))) {
                IWbemClassObject* pInClass = NULL;
                if (SUCCEEDED(pClass->GetMethod(_bstr_t(L"Restore"), 0, &pInClass, NULL))) {
                    IWbemClassObject* pInInst = NULL;
                    pInClass->SpawnInstance(0, &pInInst);
                    VARIANT v; VariantInit(&v); v.vt = VT_I4; v.lVal = seq;
                    pInInst->Put(L"SequenceNumber", 0, &v, 0);
                    IWbemClassObject* pOut = NULL;
                    HRESULT hr2 = pSvc->ExecMethod(_bstr_t(L"SystemRestore"), _bstr_t(L"Restore"), 0, NULL, pInInst, &pOut, NULL);
                    success = SUCCEEDED(hr2);
                    VariantClear(&v);
                    if (pOut) pOut->Release();
                    pInInst->Release();
                }
                if (pInClass) pInClass->Release();
                pClass->Release();
            }
            pSvc->Release();
        }
        pLoc->Release();
    }
    if (needUninit) CoUninitialize();
    return success;
}

// ================================================================
// 스크린샷
// ================================================================
void SaveBitmapToFile(HBITMAP hBitmap, const wstring& path) {
    HDC hdc = GetDC(NULL);
    BITMAP bmp; GetObject(hBitmap, sizeof(BITMAP), &bmp);
    BITMAPINFOHEADER bi{};
    bi.biSize = sizeof(BITMAPINFOHEADER);
    bi.biWidth = bmp.bmWidth; bi.biHeight = bmp.bmHeight;
    bi.biPlanes = 1; bi.biBitCount = 24; bi.biCompression = BI_RGB;
    DWORD imageSize = ((bmp.bmWidth * 3 + 3) & ~3) * bmp.bmHeight;
    bi.biSizeImage = imageSize;
    vector<BYTE> buffer(imageSize);
    GetDIBits(hdc, hBitmap, 0, bmp.bmHeight, buffer.data(), (BITMAPINFO*)&bi, DIB_RGB_COLORS);
    BITMAPFILEHEADER bf{};
    bf.bfType = 0x4D42;
    bf.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
    bf.bfSize = bf.bfOffBits + imageSize;
    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD written;
        WriteFile(hFile, &bf, sizeof(bf), &written, NULL);
        WriteFile(hFile, &bi, sizeof(bi), &written, NULL);
        WriteFile(hFile, buffer.data(), imageSize, &written, NULL);
        CloseHandle(hFile);
    }
    ReleaseDC(NULL, hdc);
}
wstring CaptureScreenshot(const wstring& savePath) {
    int w = GetSystemMetrics(SM_CXSCREEN), h = GetSystemMetrics(SM_CYSCREEN);
    HDC hScreenDC = GetDC(NULL);
    HDC hMemDC = CreateCompatibleDC(hScreenDC);
    HBITMAP hBmp = CreateCompatibleBitmap(hScreenDC, w, h);
    HBITMAP hOld = (HBITMAP)SelectObject(hMemDC, hBmp);
    BitBlt(hMemDC, 0, 0, w, h, hScreenDC, 0, 0, SRCCOPY);
    SelectObject(hMemDC, hOld);
    SaveBitmapToFile(hBmp, savePath);
    DeleteObject(hBmp); DeleteDC(hMemDC); ReleaseDC(NULL, hScreenDC);
    return savePath;
}

// ================================================================
// 검사 (Windows Defender 연동 + 의심 지표 휴리스틱)
// ================================================================
bool IsFileSigned(const wstring& path) {
    WINTRUST_FILE_INFO fileInfo{};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = path.c_str();
    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA data{};
    data.cbStruct = sizeof(data);
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE;
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    data.pFile = &fileInfo;
    LONG status = WinVerifyTrust(NULL, &action, &data);
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &action, &data);
    return status == ERROR_SUCCESS;
}

// 실행중인 모든 프로세스 중 "임시폴더 실행" 또는 "서명 없음"인 것만 추려서 listBox에 표시
// ※ 확정 판별이 아니라 "확인해볼 후보"를 추리는 휴리스틱입니다.
int ScanSuspiciousProcesses(HWND listBox) {
    SendMessageW(listBox, LB_RESETCONTENT, 0, 0);
    int flagged = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
            if (!hProc) continue;
            wchar_t pathBuf[MAX_PATH]; DWORD size = MAX_PATH;
            if (QueryFullProcessImageNameW(hProc, 0, pathBuf, &size)) {
                wstring p = pathBuf;
                bool suspiciousLoc = (p.find(L"\\Temp\\") != wstring::npos ||
                                      p.find(L"\\AppData\\Local\\Temp\\") != wstring::npos);
                bool isSigned = IsFileSigned(p);
                if (suspiciousLoc || !isSigned) {
                    wstring reason;
                    if (suspiciousLoc) reason += L"임시폴더에서 실행 ";
                    if (!isSigned) reason += L"디지털 서명 없음";
                    wstring s = wstring(pe.szExeFile) + L"  |  " + p + L"  |  " + reason;
                    SendMessageW(listBox, LB_ADDSTRING, 0, (LPARAM)s.c_str());
                    WriteLog(L"[의심지표] " + s, L"경고");
                    flagged++;
                }
            }
            CloseHandle(hProc);
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    if (flagged == 0) SendMessageW(listBox, LB_ADDSTRING, 0, (LPARAM)L"의심스러운 프로세스가 발견되지 않았습니다.");
    return flagged;
}

// Windows Defender 실제 검사 실행 (콘솔 보이게 - 진행상황 확인 가능)
bool RunDefenderScan(int scanType) { // 1=빠른검사, 2=전체검사
    wchar_t programFiles[MAX_PATH];
    if (!GetEnvironmentVariableW(L"ProgramFiles", programFiles, MAX_PATH)) wcscpy(programFiles, L"C:\\Program Files");
    wstring exePath = wstring(programFiles) + L"\\Windows Defender\\MpCmdRun.exe";
    if (GetFileAttributesW(exePath.c_str()) == INVALID_FILE_ATTRIBUTES) return false;
    wstring args = L"-Scan -ScanType " + to_wstring(scanType);
    HINSTANCE r = ShellExecuteW(NULL, L"open", exePath.c_str(), args.c_str(), NULL, SW_SHOWNORMAL);
    return ((INT_PTR)r) > 32;
}

// ================================================================
// 자체 검사 엔진 - 기본 블랙리스트 / 패턴 시드값
// ================================================================
void SeedDefaults() {
    if (g_hashBlacklist.empty()) {
        // EICAR 표준 테스트 파일의 SHA-256 (전세계 백신이 동작 확인용으로 쓰는 공인 테스트 샘플)
        g_hashBlacklist.push_back(L"275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0");
    }
    if (g_patternList.empty()) {
        g_patternList = {
            "Your files have been encrypted",
            "YOUR FILES ARE ENCRYPTED",
            "bitcoin wallet",
            "vssadmin delete shadows",
            "bcdedit /set {default} recoveryenabled no",
            "powershell -enc",
            "powershell -nop -w hidden",
            "IEX(New-Object Net.WebClient).DownloadString",
            "Invoke-Mimikatz",
            ".onion/"
        };
    }
}
wstring BytesToLowerHex(const string& s) {
    wstring out; char buf[3];
    for (unsigned char c : s) { sprintf(buf, "%02x", c); out += wstring(buf, buf + 2); }
    return out;
}

// ================================================================
// 격리 폴더로 파일 이동
// ================================================================
bool QuarantineFile(const wstring& path) {
    wstring fileName = path.substr(path.find_last_of(L"\\/") + 1);
    wstring dest = g_quarantineDir + L"\\" + NowTimeStamp() + L"_" + fileName;
    if (MoveFileW(path.c_str(), dest.c_str())) {
        g_quarantineItems.push_back({ NowReadable(), L"파일 격리", path + L" → " + dest });
        SaveState();
        WriteLog(L"파일 격리: " + path + L" -> " + dest, L"경고");
        return true;
    }
    WriteLog(L"파일 격리 실패: " + path, L"오류");
    return false;
}

// ================================================================
// 자체 검사 엔진 - 파일 한 개 검사 (해시 블랙리스트 + 패턴 + 휴리스틱)
// ================================================================
void ScanOneFile(const wstring& path, int& flaggedCount) {
    WIN32_FILE_ATTRIBUTE_DATA attr;
    if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &attr)) return;
    ULONGLONG size = ((ULONGLONG)attr.nFileSizeHigh << 32) | attr.nFileSizeLow;
    vector<wstring> reasons;

    // ① 해시 블랙리스트 - 너무 큰 파일(200MB 초과)은 속도상 전체 해시를 건너뜀
    if (size <= 200ULL * 1024 * 1024) {
        wstring hash = Sha256File(path);
        if (!hash.empty()) {
            for (auto& bl : g_hashBlacklist) {
                if (_wcsicmp(hash.c_str(), bl.c_str()) == 0) { reasons.push_back(L"블랙리스트 해시 일치"); break; }
            }
        }
    }

    // ② 패턴(문자열) 시그니처 - 파일 앞부분 최대 2MB만 검사 (속도 고려)
    {
        HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            DWORD cap = 2 * 1024 * 1024;
            DWORD toRead = (DWORD)min<ULONGLONG>(size, cap);
            if (toRead > 0) {
                vector<char> buf(toRead);
                DWORD readN = 0;
                if (ReadFile(hFile, buf.data(), toRead, &readN, NULL) && readN > 0) {
                    string content(buf.data(), readN);
                    for (auto& pat : g_patternList) {
                        if (content.find(pat) != string::npos)
                            reasons.push_back(L"의심 패턴: " + wstring(pat.begin(), pat.end()));
                    }
                }
            }
            CloseHandle(hFile);
        }
    }

    // ③ 휴리스틱 - 실행파일류가 "서명 없음 + 임시폴더 실행"인 경우만 표시 (오탐 줄이기 위해 둘 다 해당할 때만)
    wstring ext;
    size_t dot = path.find_last_of(L'.');
    if (dot != wstring::npos) ext = path.substr(dot);
    for (auto& c : ext) c = towlower(c);
    if (ext == L".exe" || ext == L".dll" || ext == L".scr" || ext == L".com") {
        bool suspiciousLoc = (path.find(L"\\Temp\\") != wstring::npos || path.find(L"\\AppData\\Local\\Temp\\") != wstring::npos);
        if (suspiciousLoc && !IsFileSigned(path)) reasons.push_back(L"서명없음 + 임시폴더 실행파일");
    }

    if (!reasons.empty()) {
        wstring reasonStr;
        for (size_t i = 0; i < reasons.size(); i++) { if (i) reasonStr += L" / "; reasonStr += reasons[i]; }
        wstring line = path + L"   [" + reasonStr + L"]";
        SendMessageW(g_lstScan, LB_ADDSTRING, 0, (LPARAM)line.c_str());
        g_scanResultPaths.push_back(path);
        WriteLog(L"[검사] " + line, L"경고");
        flaggedCount++;
    }
}

void ScanWalk(const wstring& folder, int& scanned, int& flagged) {
    if (g_scanCancel) return;
    WIN32_FIND_DATAW fd;
    wstring pattern = folder + L"\\*";
    HANDLE h = FindFirstFileW(pattern.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (g_scanCancel) break;
        wstring name = fd.cFileName;
        if (name == L"." || name == L"..") continue;
        wstring full = folder + L"\\" + name;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) continue; // 심볼릭링크/정션 - 무한루프 방지
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            ScanWalk(full, scanned, flagged);
        } else {
            scanned++;
            ScanOneFile(full, flagged);
            if (scanned % 50 == 0) {
                wstring prog = L"검사 중... 파일 " + to_wstring(scanned) + L"개 확인  |  의심 발견 " + to_wstring(flagged) + L"건";
                SetWindowTextW(g_lblScanProgress, prog.c_str());
            }
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

DWORD WINAPI ScanWorkerProc(LPVOID) {
    wchar_t rootBuf[MAX_PATH] = L"";
    GetWindowTextW(g_edtScanRoot, rootBuf, MAX_PATH);
    wstring root = rootBuf;
    if (root.empty()) root = L"C:\\";
    g_scanCancel = false;
    g_scanRunning = true;
    SendMessageW(g_lstScan, LB_RESETCONTENT, 0, 0);
    g_scanResultPaths.clear();
    int scanned = 0, flagged = 0;
    WriteLog(L"자체 엔진 전체 검사 시작: " + root);
    ScanWalk(root, scanned, flagged);
    g_scanRunning = false;
    wstring finalMsg = g_scanCancel ? L"검사 중지됨" : L"검사 완료";
    wstring prog = finalMsg + L" - 파일 " + to_wstring(scanned) + L"개 확인  |  의심 발견 " + to_wstring(flagged) + L"건";
    SetWindowTextW(g_lblScanProgress, prog.c_str());
    WriteLog(finalMsg + L" (검사 " + to_wstring(scanned) + L"개, 발견 " + to_wstring(flagged) + L"건)");
    PostMessageW(g_hMain, WM_SCAN_DONE, 0, 0);
    return 0;
}

// ================================================================
// 실시간 위협 인텔리전스 업데이트 (abuse.ch MalwareBazaar 공개 피드)
// 이 사이트는 보안 담당자가 방어용 블랙리스트로 쓰라고 공식 공개하는 곳입니다.
// 무료 Auth-Key 발급: https://auth.abuse.ch
// ================================================================
bool HttpGetSecure(const wstring& host, const wstring& path, string& outBody, wstring& err) {
    HINTERNET hSession = WinHttpOpen(L"PCGuardian/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) { err = L"WinHttpOpen 실패"; return false; }
    HINTERNET hConnect = WinHttpConnect(hSession, host.c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) { err = L"서버 연결 실패"; WinHttpCloseHandle(hSession); return false; }
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", path.c_str(), NULL,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hRequest) { err = L"요청 생성 실패"; WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return false; }

    BOOL ok = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    if (ok) ok = WinHttpReceiveResponse(hRequest, NULL);
    if (ok) {
        DWORD avail = 0;
        while (WinHttpQueryDataAvailable(hRequest, &avail) && avail > 0) {
            vector<char> buf(avail);
            DWORD readN = 0;
            if (WinHttpReadData(hRequest, buf.data(), avail, &readN)) outBody.append(buf.data(), readN);
            else break;
        }
    } else {
        err = L"요청 실패 (오류코드 " + to_wstring(GetLastError()) + L")";
    }
    WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession);
    return !outBody.empty();
}

vector<string> ParseCsvLine(const string& line) {
    vector<string> out; string cur; bool inQuotes = false;
    for (char c : line) {
        if (c == '"') inQuotes = !inQuotes;
        else if (c == ',' && !inQuotes) { out.push_back(cur); cur.clear(); }
        else cur += c;
    }
    out.push_back(cur);
    return out;
}
bool IsHex64(const string& s) {
    if (s.size() != 64) return false;
    for (char c : s) if (!isxdigit((unsigned char)c)) return false;
    return true;
}
// MalwareBazaar CSV 형식: first_seen_utc, sha256_hash, md5_hash, sha1_hash, ...
int ImportCsvHashes(const string& csv) {
    int count = 0;
    stringstream ss(csv); string line;
    while (getline(ss, line)) {
        if (line.empty() || line[0] == '#') continue;
        auto fields = ParseCsvLine(line);
        if (fields.size() < 2) continue;
        string hash = fields[1];
        if (IsHex64(hash)) {
            wstring whash(hash.begin(), hash.end());
            g_hashBlacklist.push_back(whash);
            count++;
        }
    }
    return count;
}
bool UpdateThreatIntel(wstring& statusMsg) {
    if (g_mbApiKey.empty()) { statusMsg = L"Auth-Key를 먼저 입력해주세요. (무료 발급: auth.abuse.ch)"; return false; }
    wstring path = L"/v2/files/exports/" + g_mbApiKey + L"/recent.csv";
    string body; wstring err;
    if (!HttpGetSecure(L"mb-api.abuse.ch", path, body, err)) {
        statusMsg = L"다운로드 실패: " + err;
        return false;
    }
    int count = ImportCsvHashes(body);
    if (count == 0) {
        statusMsg = L"받아온 데이터에서 해시를 찾지 못했습니다. Auth-Key가 올바른지 확인해주세요.";
        return false;
    }
    statusMsg = L"해시 " + to_wstring(count) + L"개를 블랙리스트에 추가했습니다. (최근 48시간 신규 악성코드)";
    WriteLog(L"위협 인텔리전스 업데이트: " + to_wstring(count) + L"개 해시 추가");
    return true;
}

// ================================================================
// GUI 갱신 함수들
// ================================================================
void RefreshDashboard() {
    wstring lastSnap = L"없음";
    SetWindowTextW(g_lblBlocked, to_wstring(g_blockedIPs.size()).c_str());
    SetWindowTextW(g_lblQuar, to_wstring(g_quarantineItems.size()).c_str());

    SendMessageW(g_lstDashRecent, LB_RESETCONTENT, 0, 0);
    wstring logPath = g_logDir + L"\\guardian_" + NowDateStamp() + L".log";
    wifstream f((logPath).c_str()); wstring line; vector<wstring> lines;
    while (getline(f, line)) lines.push_back(line);
    int start = (int)lines.size() > 30 ? (int)lines.size() - 30 : 0;
    for (int i = (int)lines.size() - 1; i >= start; i--)
        SendMessageW(g_lstDashRecent, LB_ADDSTRING, 0, (LPARAM)lines[i].c_str());
}
void RefreshBlockedList() {
    SendMessageW(g_lstBlocked, LB_RESETCONTENT, 0, 0);
    for (auto& b : g_blockedIPs) {
        wstring s = b.ip + L"   |   " + b.time + L"   |   " + b.reason;
        SendMessageW(g_lstBlocked, LB_ADDSTRING, 0, (LPARAM)s.c_str());
    }
}
void RefreshFolderList() {
    SendMessageW(g_lstFolders, LB_RESETCONTENT, 0, 0);
    for (auto& p : g_watchedFolders) SendMessageW(g_lstFolders, LB_ADDSTRING, 0, (LPARAM)p.c_str());
}
void RefreshQuarHistory() {
    SendMessageW(g_lstQuarHist, LB_RESETCONTENT, 0, 0);
    for (auto& q : g_quarantineItems) {
        wstring s = q.time + L"  |  " + q.type + L"  |  " + q.target;
        SendMessageW(g_lstQuarHist, LB_ADDSTRING, 0, (LPARAM)s.c_str());
    }
}
void RefreshEvidenceList() {
    SendMessageW(g_lstEvidence, LB_RESETCONTENT, 0, 0);
    WIN32_FIND_DATAW fd;
    wstring pattern = g_evidenceDir + L"\\*";
    HANDLE h = FindFirstFileW(pattern.c_str(), &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            wstring name = fd.cFileName;
            if (name == L"." || name == L"..") continue;
            SendMessageW(g_lstEvidence, LB_ADDSTRING, 0, (LPARAM)name.c_str());
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    }
}
void RefreshLogView() {
    SendMessageW(g_lstLog, LB_RESETCONTENT, 0, 0);
    wstring logPath = g_logDir + L"\\guardian_" + NowDateStamp() + L".log";
    wifstream f((logPath).c_str()); wstring line; vector<wstring> lines;
    while (getline(f, line)) lines.push_back(line);
    for (int i = (int)lines.size() - 1; i >= 0; i--)
        SendMessageW(g_lstLog, LB_ADDSTRING, 0, (LPARAM)lines[i].c_str());
}
void RefreshRestorePoints() {
    SendMessageW(g_lstRestore, LB_RESETCONTENT, 0, 0);
    auto points = ListRestorePoints();
    for (auto& p : points) {
        wstring s = L"#" + to_wstring(p.seq) + L"  |  " + p.created.substr(0, min<size_t>(14, p.created.size())) + L"  |  " + p.desc;
        SendMessageW(g_lstRestore, LB_ADDSTRING, 0, (LPARAM)s.c_str());
    }
}
void RefreshProcessList() {
    SendMessageW(g_lstProc, LB_RESETCONTENT, 0, 0);
    g_procListPids.clear();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            wstring s = wstring(pe.szExeFile) + L"  (PID " + to_wstring(pe.th32ProcessID) + L")";
            SendMessageW(g_lstProc, LB_ADDSTRING, 0, (LPARAM)s.c_str());
            g_procListPids.push_back(pe.th32ProcessID);
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
}

// ================================================================
// 패널 전환
// ================================================================
void ShowPanel(int idx) {
    for (int i = 0; i < 9; i++) ShowWindow(g_panels[i], i == idx ? SW_SHOW : SW_HIDE);
    if (idx == 0) RefreshDashboard();
    if (idx == 2) RefreshBlockedList();
    if (idx == 3) RefreshFolderList();
    if (idx == 4) RefreshRestorePoints();
    if (idx == 5) RefreshQuarHistory();
    if (idx == 6) RefreshEvidenceList();
    if (idx == 7) RefreshLogView();
}

// ================================================================
// 컨트롤 생성 헬퍼
// ================================================================
HWND MkButton(HWND parent, const wchar_t* text, int x, int y, int w, int h, int id) {
    return CreateWindowW(L"BUTTON", text, WS_CHILD | WS_VISIBLE, x, y, w, h, parent, (HMENU)(INT_PTR)id, NULL, NULL);
}
HWND MkStatic(HWND parent, const wchar_t* text, int x, int y, int w, int h) {
    return CreateWindowW(L"STATIC", text, WS_CHILD | WS_VISIBLE, x, y, w, h, parent, NULL, NULL, NULL);
}
HWND MkEdit(HWND parent, const wchar_t* text, int x, int y, int w, int h) {
    return CreateWindowW(L"EDIT", text, WS_CHILD | WS_VISIBLE | WS_BORDER, x, y, w, h, parent, NULL, NULL, NULL);
}
HWND MkList(HWND parent, int x, int y, int w, int h) {
    return CreateWindowW(L"LISTBOX", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL | LBS_NOTIFY,
        x, y, w, h, parent, NULL, NULL, NULL);
}
HWND MkPanel(HWND parent) {
    return CreateWindowW(L"STATIC", L"", WS_CHILD, 190, 0, 860, 700, parent, NULL, NULL, NULL);
}

// ================================================================
// 메인 윈도우 프로시저
// ================================================================
LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        // ---- 사이드바 ----
        MkStatic(hwnd, L"PC-Guardian", 20, 20, 150, 24);
        const wchar_t* navLabels[9] = { L"대시보드", L"실시간 감시", L"침입 차단", L"파일 무결성", L"복구/백업", L"격리함", L"증거/신고", L"로그", L"🔎 검사" };
        int navIds[9] = { ID_NAV_DASH, ID_NAV_WATCH, ID_NAV_FW, ID_NAV_FILE, ID_NAV_RESTORE, ID_NAV_QUAR, ID_NAV_EVID, ID_NAV_LOG, ID_NAV_SCAN };
        for (int i = 0; i < 9; i++) MkButton(hwnd, navLabels[i], 10, 60 + i * 40, 170, 34, navIds[i]);

        // ---- 패널 0: 대시보드 ----
        g_panels[0] = MkPanel(hwnd);
        MkStatic(g_panels[0], L"대시보드", 20, 16, 200, 24);
        MkStatic(g_panels[0], L"차단된 IP 수:", 20, 60, 120, 20);
        g_lblBlocked = MkStatic(g_panels[0], L"0", 150, 60, 80, 20);
        MkStatic(g_panels[0], L"격리된 항목:", 20, 85, 120, 20);
        g_lblQuar = MkStatic(g_panels[0], L"0", 150, 85, 80, 20);
        MkButton(g_panels[0], L"지금 상태 스냅샷", 20, 120, 150, 30, ID_DASH_SNAP);
        MkButton(g_panels[0], L"보호 지점 만들기", 180, 120, 150, 30, ID_DASH_PROTECT);
        MkStatic(g_panels[0], L"최근 활동", 20, 165, 150, 20);
        g_lstDashRecent = MkList(g_panels[0], 20, 190, 800, 420);

        // ---- 패널 1: 실시간 감시 ----
        g_panels[1] = MkPanel(hwnd);
        MkStatic(g_panels[1], L"실시간 감시", 20, 16, 200, 24);
        MkStatic(g_panels[1], L"확인 주기(분):", 20, 60, 100, 20);
        g_edtWatchInterval = MkEdit(g_panels[1], L"10", 130, 58, 50, 24);
        MkButton(g_panels[1], L"감시 시작", 200, 56, 90, 28, ID_WATCH_START);
        MkButton(g_panels[1], L"감시 중지", 300, 56, 90, 28, ID_WATCH_STOP);
        MkStatic(g_panels[1], L"변화 감지 내역", 20, 100, 150, 20);
        g_lstWatch = MkList(g_panels[1], 20, 125, 800, 480);

        // ---- 패널 2: 침입 차단 ----
        g_panels[2] = MkPanel(hwnd);
        MkStatic(g_panels[2], L"침입 차단", 20, 16, 200, 24);
        MkStatic(g_panels[2], L"① RDP 로그인 실패 자동 차단 (fail2ban 방식)", 20, 56, 400, 20);
        MkStatic(g_panels[2], L"허용 실패 횟수:", 20, 84, 100, 20);
        g_edtFwThreshold = MkEdit(g_panels[2], L"5", 130, 82, 40, 24);
        MkButton(g_panels[2], L"자동 차단 시작", 190, 80, 110, 28, ID_FW_START);
        MkButton(g_panels[2], L"감시 중지", 310, 80, 90, 28, ID_FW_STOP);

        MkStatic(g_panels[2], L"② 수동 IP/대역 차단", 20, 126, 300, 20);
        g_edtManualIP = MkEdit(g_panels[2], L"", 20, 150, 220, 24);
        MkButton(g_panels[2], L"차단 추가", 250, 148, 90, 28, ID_FW_BLOCK);
        MkButton(g_panels[2], L"목록파일 불러오기", 350, 148, 130, 28, ID_FW_IMPORT);

        MkStatic(g_panels[2], L"현재 차단 목록", 20, 190, 150, 20);
        g_lstBlocked = MkList(g_panels[2], 20, 215, 800, 300);
        MkButton(g_panels[2], L"선택 항목 차단 해제", 20, 525, 160, 28, ID_FW_UNBLOCK);

        // ---- 패널 3: 파일 무결성 ----
        g_panels[3] = MkPanel(hwnd);
        MkStatic(g_panels[3], L"파일 무결성 검사", 20, 16, 200, 24);
        MkButton(g_panels[3], L"감시 폴더 추가", 20, 56, 120, 28, ID_FILE_ADDFOLDER);
        MkButton(g_panels[3], L"기준 해시 생성", 150, 56, 120, 28, ID_FILE_BASELINE);
        MkButton(g_panels[3], L"지금 검사", 280, 56, 100, 28, ID_FILE_CHECK);
        MkStatic(g_panels[3], L"감시 중인 폴더", 20, 98, 150, 20);
        g_lstFolders = MkList(g_panels[3], 20, 122, 800, 100);
        MkStatic(g_panels[3], L"검사 결과", 20, 232, 150, 20);
        g_lstFileResult = MkList(g_panels[3], 20, 256, 800, 350);

        // ---- 패널 4: 복구/백업 ----
        g_panels[4] = MkPanel(hwnd);
        MkStatic(g_panels[4], L"복구 / 백업", 20, 16, 200, 24);
        MkButton(g_panels[4], L"복원 지점 생성", 20, 56, 120, 28, ID_RESTORE_CREATE);
        MkButton(g_panels[4], L"목록 새로고침", 150, 56, 120, 28, ID_RESTORE_REFRESH);
        MkStatic(g_panels[4], L"복원 지점 목록", 20, 98, 150, 20);
        g_lstRestore = MkList(g_panels[4], 20, 122, 800, 420);
        MkButton(g_panels[4], L"선택 지점으로 되돌리기", 20, 552, 180, 30, ID_RESTORE_DO);

        // ---- 패널 5: 격리함 ----
        g_panels[5] = MkPanel(hwnd);
        MkStatic(g_panels[5], L"격리함", 20, 16, 200, 24);
        MkButton(g_panels[5], L"실행중인 프로그램 보기", 20, 56, 170, 28, ID_QUAR_REFRESH);
        MkButton(g_panels[5], L"선택 프로그램 종료(격리)", 200, 56, 180, 28, ID_QUAR_KILL);
        g_lstProc = MkList(g_panels[5], 20, 96, 800, 240);
        MkStatic(g_panels[5], L"격리 이력", 20, 346, 150, 20);
        g_lstQuarHist = MkList(g_panels[5], 20, 370, 800, 220);

        // ---- 패널 6: 증거/신고 ----
        g_panels[6] = MkPanel(hwnd);
        MkStatic(g_panels[6], L"증거 수집 / 신고", 20, 16, 200, 24);
        MkButton(g_panels[6], L"스크린샷 캡처", 20, 56, 110, 28, ID_EVID_SCREENSHOT);
        MkButton(g_panels[6], L"증거 폴더 생성", 140, 56, 150, 28, ID_EVID_COLLECT);
        MkButton(g_panels[6], L"신고 리포트 생성", 300, 56, 150, 28, ID_EVID_REPORT);
        MkStatic(g_panels[6],
            L"공식 신고 창구\r\n"
            L"- KISA 118센터 (인터넷 침해사고 신고) kisa.or.kr / 국번없이 118\r\n"
            L"- 경찰청 사이버수사국  ecrm.cyber.go.kr\r\n"
            L"신고 시 수사기관이 통신사에 영장을 받아 실제 가입자 정보를 확인합니다.",
            20, 100, 780, 80);
        MkStatic(g_panels[6], L"생성된 증거 폴더/파일 목록", 20, 190, 220, 20);
        g_lstEvidence = MkList(g_panels[6], 20, 215, 800, 350);

        // ---- 패널 7: 로그 ----
        g_panels[7] = MkPanel(hwnd);
        MkStatic(g_panels[7], L"로그", 20, 16, 200, 24);
        MkButton(g_panels[7], L"새로고침", 20, 56, 100, 28, ID_LOG_REFRESH);
        MkButton(g_panels[7], L"로그 폴더 열기", 130, 56, 120, 28, ID_LOG_OPENFOLDER);
        g_lstLog = MkList(g_panels[7], 20, 96, 800, 560);

        // ---- 패널 8: 검사 (Defender 연동 + 자체 엔진) ----
        g_panels[8] = MkPanel(hwnd);
        MkStatic(g_panels[8], L"검사", 20, 16, 200, 24);

        MkStatic(g_panels[8], L"① Windows Defender 실제 검사 실행", 20, 54, 320, 20);
        MkButton(g_panels[8], L"빠른 검사", 20, 78, 100, 28, ID_SCAN_DEFENDER_QUICK);
        MkButton(g_panels[8], L"전체 검사(드라이브 전체)", 130, 78, 180, 28, ID_SCAN_DEFENDER_FULL);

        MkStatic(g_panels[8], L"② 실시간 위협 인텔리전스 (abuse.ch MalwareBazaar 공개 피드)", 20, 122, 500, 20);
        MkStatic(g_panels[8], L"Auth-Key:", 20, 148, 70, 20);
        g_edtMbKey = MkEdit(g_panels[8], L"", 90, 146, 220, 24);
        MkButton(g_panels[8], L"최신 위협정보 업데이트", 320, 144, 160, 28, ID_SCAN_UPDATE_FEED);
        MkStatic(g_panels[8], L"무료 발급: auth.abuse.ch  (최근 48시간 신규 악성코드 해시를 받아옵니다)", 20, 172, 500, 18);

        MkStatic(g_panels[8], L"③ 자체 엔진 - 드라이브 전체 검사 (블랙리스트 + 패턴 + 휴리스틱)", 20, 198, 500, 20);
        MkStatic(g_panels[8], L"검사할 경로:", 20, 224, 90, 20);
        g_edtScanRoot = MkEdit(g_panels[8], L"C:\\", 110, 222, 150, 24);
        MkButton(g_panels[8], L"검사 시작", 270, 220, 90, 28, ID_SCAN_START);
        MkButton(g_panels[8], L"검사 중지", 365, 220, 90, 28, ID_SCAN_STOP);
        MkButton(g_panels[8], L"해시 파일 추가", 465, 220, 120, 28, ID_SCAN_IMPORT_HASH);
        MkButton(g_panels[8], L"패턴 파일 추가", 595, 220, 120, 28, ID_SCAN_IMPORT_PATTERN);

        g_lblScanProgress = MkStatic(g_panels[8], L"대기 중  (현재 블랙리스트 해시 수: -)", 20, 256, 700, 20);
        g_lstScan = MkList(g_panels[8], 20, 280, 800, 284);
        MkButton(g_panels[8], L"선택 결과 격리", 20, 572, 140, 28, ID_SCAN_QUARANTINE);

        if (!g_mbApiKey.empty()) SetWindowTextW(g_edtMbKey, g_mbApiKey.c_str());
        ShowPanel(0);
        break;
    }

    case WM_TIMER: {
        if (wParam == ID_TIMER_WATCH) {
            auto proc = GetProcessList();
            auto startup = GetStartupList();
            auto bt = GetBluetoothList();
            auto d1 = DiffNew(g_watchBaseline_proc, proc);
            auto d2 = DiffNew(g_watchBaseline_startup, startup);
            auto d3 = DiffNew(g_watchBaseline_bt, bt);
            wstring stamp = L"── " + NowReadable() + L" ──";
            if (!d1.empty() || !d2.empty() || !d3.empty()) {
                SendMessageW(g_lstWatch, LB_INSERTSTRING, 0, (LPARAM)stamp.c_str());
                int pos = 1;
                for (auto& x : d1) { wstring s = L"[새 프로그램] " + x; SendMessageW(g_lstWatch, LB_INSERTSTRING, pos++, (LPARAM)s.c_str()); WriteLog(s, L"경고"); }
                for (auto& x : d2) { wstring s = L"[새 시작프로그램] " + x; SendMessageW(g_lstWatch, LB_INSERTSTRING, pos++, (LPARAM)s.c_str()); WriteLog(s, L"경고"); }
                for (auto& x : d3) { wstring s = L"[새 블루투스 기기] " + x; SendMessageW(g_lstWatch, LB_INSERTSTRING, pos++, (LPARAM)s.c_str()); WriteLog(s, L"경고"); }
            } else {
                wstring s = L"[" + NowReadable() + L"] 변화 없음";
                SendMessageW(g_lstWatch, LB_INSERTSTRING, 0, (LPARAM)s.c_str());
            }
            g_watchBaseline_proc = proc; g_watchBaseline_startup = startup; g_watchBaseline_bt = bt;
        } else if (wParam == ID_TIMER_FW) {
            int threshold = 5;
            wchar_t buf[16]; GetWindowTextW(g_edtFwThreshold, buf, 16); threshold = _wtoi(buf); if (threshold < 1) threshold = 5;
            CheckFailedLogons(threshold);
            RefreshBlockedList();
        }
        break;
    }

    case WM_COMMAND: {
        int id = LOWORD(wParam);
        switch (id) {
        case ID_NAV_DASH: ShowPanel(0); break;
        case ID_NAV_WATCH: ShowPanel(1); break;
        case ID_NAV_FW: ShowPanel(2); break;
        case ID_NAV_FILE: ShowPanel(3); break;
        case ID_NAV_RESTORE: ShowPanel(4); break;
        case ID_NAV_QUAR: ShowPanel(5); break;
        case ID_NAV_EVID: ShowPanel(6); break;
        case ID_NAV_LOG: ShowPanel(7); break;
        case ID_NAV_SCAN: ShowPanel(8); break;

        case ID_DASH_SNAP: {
            WriteLog(L"수동 스냅샷 생성");
            MessageBoxW(hwnd, L"현재 상태를 기록했습니다.", L"완료", MB_OK);
            RefreshDashboard();
            break;
        }
        case ID_DASH_PROTECT: {
            bool ok = CreateRestorePoint(L"PC-Guardian 보호지점");
            if (ok) { WriteLog(L"보호 지점 생성 완료"); MessageBoxW(hwnd, L"보호 지점이 생성되었습니다.", L"완료", MB_OK); }
            else { WriteLog(L"보호 지점 생성 실패", L"오류"); MessageBoxW(hwnd, L"생성 실패. 관리자 권한인지 확인해주세요.", L"오류", MB_ICONERROR); }
            break;
        }
        case ID_WATCH_START: {
            wchar_t buf[16]; GetWindowTextW(g_edtWatchInterval, buf, 16);
            int min = _wtoi(buf); if (min < 1) min = 10;
            g_watchBaseline_proc = GetProcessList();
            g_watchBaseline_startup = GetStartupList();
            g_watchBaseline_bt = GetBluetoothList();
            SetTimer(hwnd, ID_TIMER_WATCH, min * 60 * 1000, NULL);
            WriteLog(L"실시간 감시 시작 (주기 " + to_wstring(min) + L"분)");
            break;
        }
        case ID_WATCH_STOP: KillTimer(hwnd, ID_TIMER_WATCH); WriteLog(L"실시간 감시 중지"); break;

        case ID_FW_START: {
            SetTimer(hwnd, ID_TIMER_FW, 60 * 1000, NULL);
            WriteLog(L"RDP 로그인 실패 자동 차단 감시 시작");
            MessageBoxW(hwnd, L"자동 차단 감시를 시작했습니다.\n(1분마다 최근 10분 내 로그인 실패를 확인합니다)", L"시작됨", MB_OK);
            break;
        }
        case ID_FW_STOP: KillTimer(hwnd, ID_TIMER_FW); WriteLog(L"RDP 자동 차단 감시 중지"); break;

        case ID_FW_BLOCK: {
            wchar_t buf[128]; GetWindowTextW(g_edtManualIP, buf, 128);
            wstring ip = buf;
            if (!ip.empty()) {
                bool ok = BlockIP(ip, L"수동 차단");
                if (ok) { SetWindowTextW(g_edtManualIP, L""); RefreshBlockedList(); RefreshDashboard(); }
                else MessageBoxW(hwnd, L"차단 실패. 관리자 권한과 IP 형식을 확인해주세요.", L"오류", MB_ICONERROR);
            }
            break;
        }
        case ID_FW_IMPORT: {
            wchar_t fileName[MAX_PATH] = L"";
            OPENFILENAMEW ofn{}; ofn.lStructSize = sizeof(ofn); ofn.hwndOwner = hwnd;
            ofn.lpstrFilter = L"텍스트 파일\0*.txt\0모든 파일\0*.*\0";
            ofn.lpstrFile = fileName; ofn.nMaxFile = MAX_PATH;
            ofn.lpstrTitle = L"차단할 IP/대역 목록 파일 선택";
            ofn.Flags = OFN_FILEMUSTEXIST;
            if (GetOpenFileNameW(&ofn)) {
                wifstream f(fileName); wstring line; int count = 0;
                while (getline(f, line)) {
                    size_t s = line.find_first_not_of(L" \t\r\n");
                    if (s == wstring::npos) continue;
                    size_t e = line.find_last_not_of(L" \t\r\n");
                    wstring ip = line.substr(s, e - s + 1);
                    if (BlockIP(ip, L"목록 가져오기")) count++;
                }
                RefreshBlockedList(); RefreshDashboard();
                MessageBoxW(hwnd, (L"차단 완료: " + to_wstring(count) + L"개").c_str(), L"완료", MB_OK);
            }
            break;
        }
        case ID_FW_UNBLOCK: {
            int sel = (int)SendMessageW(g_lstBlocked, LB_GETCURSEL, 0, 0);
            if (sel != LB_ERR && sel < (int)g_blockedIPs.size()) {
                UnblockIP(g_blockedIPs[sel].ip);
                RefreshBlockedList(); RefreshDashboard();
            }
            break;
        }

        case ID_FILE_ADDFOLDER: {
            BROWSEINFOW bi{}; bi.hwndOwner = hwnd; bi.lpszTitle = L"감시할 폴더를 선택하세요";
            bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
            LPITEMIDLIST pidl = SHBrowseForFolderW(&bi);
            if (pidl) {
                wchar_t path[MAX_PATH];
                if (SHGetPathFromIDListW(pidl, path)) {
                    wstring p = path;
                    if (find(g_watchedFolders.begin(), g_watchedFolders.end(), p) == g_watchedFolders.end()) {
                        g_watchedFolders.push_back(p);
                        SaveState();
                        RefreshFolderList();
                        WriteLog(L"감시 폴더 추가: " + p);
                    }
                }
                CoTaskMemFree(pidl);
            }
            break;
        }
        case ID_FILE_BASELINE: {
            if (g_watchedFolders.empty()) { MessageBoxW(hwnd, L"먼저 감시 폴더를 추가해주세요.", L"안내", MB_OK); break; }
            g_fileBaseline.clear();
            for (auto& folder : g_watchedFolders) {
                vector<wstring> files; EnumFilesRecursive(folder, files);
                for (auto& f : files) { wstring h = Sha256File(f); if (!h.empty()) g_fileBaseline[f] = h; }
            }
            SaveState();
            WriteLog(L"파일 무결성 기준 해시 생성 (" + to_wstring(g_fileBaseline.size()) + L"개 파일)");
            MessageBoxW(hwnd, (L"기준 해시를 생성했습니다. (" + to_wstring(g_fileBaseline.size()) + L"개 파일)").c_str(), L"완료", MB_OK);
            break;
        }
        case ID_FILE_CHECK: {
            SendMessageW(g_lstFileResult, LB_RESETCONTENT, 0, 0);
            if (g_fileBaseline.empty()) {
                SendMessageW(g_lstFileResult, LB_ADDSTRING, 0, (LPARAM)L"기준 해시가 없습니다. 먼저 '기준 해시 생성'을 눌러주세요.");
                break;
            }
            map<wstring, wstring> current;
            for (auto& folder : g_watchedFolders) {
                vector<wstring> files; EnumFilesRecursive(folder, files);
                for (auto& f : files) { wstring h = Sha256File(f); if (!h.empty()) current[f] = h; }
            }
            int changed = 0;
            for (auto& kv : g_fileBaseline) {
                auto it = current.find(kv.first);
                if (it == current.end()) {
                    wstring s = L"[삭제됨] " + kv.first;
                    SendMessageW(g_lstFileResult, LB_ADDSTRING, 0, (LPARAM)s.c_str());
                    WriteLog(s, L"경고"); changed++;
                } else if (it->second != kv.second) {
                    wstring s = L"[변경됨] " + kv.first;
                    SendMessageW(g_lstFileResult, LB_ADDSTRING, 0, (LPARAM)s.c_str());
                    WriteLog(s, L"경고"); changed++;
                }
            }
            for (auto& kv : current) {
                if (g_fileBaseline.find(kv.first) == g_fileBaseline.end()) {
                    wstring s = L"[새 파일] " + kv.first;
                    SendMessageW(g_lstFileResult, LB_ADDSTRING, 0, (LPARAM)s.c_str());
                    changed++;
                }
            }
            if (changed == 0) SendMessageW(g_lstFileResult, LB_ADDSTRING, 0, (LPARAM)L"변화 없음 - 모든 파일이 기준과 일치합니다.");
            break;
        }

        case ID_RESTORE_CREATE: {
            bool ok = CreateRestorePoint(L"PC-Guardian 수동 생성");
            if (ok) { WriteLog(L"복원 지점 생성 완료"); MessageBoxW(hwnd, L"복원 지점이 생성되었습니다.", L"완료", MB_OK); RefreshRestorePoints(); }
            else MessageBoxW(hwnd, L"생성 실패.", L"오류", MB_ICONERROR);
            break;
        }
        case ID_RESTORE_REFRESH: RefreshRestorePoints(); break;
        case ID_RESTORE_DO: {
            int sel = (int)SendMessageW(g_lstRestore, LB_GETCURSEL, 0, 0);
            if (sel == LB_ERR) break;
            auto points = ListRestorePoints();
            if (sel >= (int)points.size()) break;
            int res = MessageBoxW(hwnd, L"선택한 복원 지점으로 되돌리시겠습니까?\nPC가 재부팅됩니다.", L"확인", MB_YESNO | MB_ICONWARNING);
            if (res == IDYES) {
                WriteLog(L"시스템 복원 실행: #" + to_wstring(points[sel].seq), L"경고");
                RestoreToPoint(points[sel].seq);
            }
            break;
        }

        case ID_QUAR_REFRESH: RefreshProcessList(); break;
        case ID_QUAR_KILL: {
            int sel = (int)SendMessageW(g_lstProc, LB_GETCURSEL, 0, 0);
            if (sel == LB_ERR || sel >= (int)g_procListPids.size()) break;
            wchar_t text[256]; SendMessageW(g_lstProc, LB_GETTEXT, sel, (LPARAM)text);
            int res = MessageBoxW(hwnd, (wstring(L"\"") + text + L"\" 프로그램을 종료하시겠습니까?").c_str(), L"확인", MB_YESNO);
            if (res == IDYES) {
                HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, g_procListPids[sel]);
                if (hProc) { TerminateProcess(hProc, 1); CloseHandle(hProc); }
                g_quarantineItems.push_back({ NowReadable(), L"프로세스 종료", text });
                SaveState();
                WriteLog(wstring(L"프로세스 격리(종료): ") + text, L"경고");
                RefreshQuarHistory(); RefreshDashboard();
                MessageBoxW(hwnd, L"종료했습니다.", L"완료", MB_OK);
            }
            break;
        }

        case ID_EVID_SCREENSHOT: {
            wstring path = g_evidenceDir + L"\\screenshot_" + NowTimeStamp() + L".bmp";
            CaptureScreenshot(path);
            WriteLog(L"스크린샷 저장: " + path);
            MessageBoxW(hwnd, (L"스크린샷을 저장했습니다.\n" + path).c_str(), L"완료", MB_OK);
            RefreshEvidenceList();
            break;
        }
        case ID_EVID_COLLECT: {
            wstring folder = g_evidenceDir + L"\\evidence_" + NowTimeStamp();
            EnsureDir(folder);
            wstring evOut = RunCapture(L"wevtutil qe Security /q:\"*[System[(EventID=4625) and TimeCreated[timediff(@SystemTime) <= 86400000]]]\" /f:text /rd:true /c:100");
            { wofstream f((folder + L"\\로그인실패기록.txt").c_str()); f << evOut; }
            { wofstream f((folder + L"\\차단된IP목록.txt").c_str()); for (auto& b : g_blockedIPs) f << b.ip << L" | " << b.time << L" | " << b.reason << L"\n"; }
            wstring logPath = g_logDir + L"\\guardian_" + NowDateStamp() + L".log";
            CopyFileW(logPath.c_str(), (folder + L"\\활동로그.txt").c_str(), FALSE);
            CaptureScreenshot(folder + L"\\화면캡처.bmp");
            WriteLog(L"증거 폴더 생성: " + folder);
            MessageBoxW(hwnd, (L"증거 자료를 모았습니다.\n" + folder).c_str(), L"완료", MB_OK);
            RefreshEvidenceList();
            break;
        }
        case ID_EVID_REPORT: {
            wstring path = g_evidenceDir + L"\\신고리포트_" + NowTimeStamp() + L".txt";
            wofstream f((path).c_str());
            f << L"====================================\n 침해사고 신고용 리포트\n 생성 시각: " << NowReadable() << L"\n====================================\n\n";
            f << L"[차단된 IP 목록]\n";
            for (auto& b : g_blockedIPs) f << L"  - " << b.ip << L"  |  차단시각: " << b.time << L"  |  사유: " << b.reason << L"\n";
            f << L"\n[격리(종료)된 프로세스]\n";
            for (auto& q : g_quarantineItems) f << L"  - " << q.target << L"  |  시각: " << q.time << L"\n";
            f << L"\n[최근 24시간 로그인 실패 이벤트]\n";
            wstring evOut = RunCapture(L"wevtutil qe Security /q:\"*[System[(EventID=4625) and TimeCreated[timediff(@SystemTime) <= 86400000]]]\" /f:text /rd:true /c:100");
            f << evOut;
            f << L"\n====================================\n 신고 접수처\n  - KISA 118센터 (kisa.or.kr / 국번없이 118)\n  - 경찰청 사이버수사국 (ecrm.cyber.go.kr)\n====================================\n";
            f.close();
            WriteLog(L"신고 리포트 생성: " + path);
            MessageBoxW(hwnd, (L"신고용 리포트를 만들었습니다.\n" + path).c_str(), L"완료", MB_OK);
            ShellExecuteW(NULL, L"open", path.c_str(), NULL, NULL, SW_SHOWNORMAL);
            RefreshEvidenceList();
            break;
        }

        case ID_LOG_REFRESH: RefreshLogView(); break;
        case ID_LOG_OPENFOLDER: ShellExecuteW(NULL, L"open", g_logDir.c_str(), NULL, NULL, SW_SHOWNORMAL); break;

        case ID_SCAN_DEFENDER_QUICK: {
            if (!RunDefenderScan(1)) MessageBoxW(hwnd, L"Windows Defender를 찾을 수 없습니다. 다른 백신이 설치되어 있다면 Defender가 꺼져있을 수 있습니다.", L"오류", MB_ICONERROR);
            else WriteLog(L"Windows Defender 빠른 검사 실행");
            break;
        }
        case ID_SCAN_DEFENDER_FULL: {
            int res = MessageBoxW(hwnd, L"전체 드라이브 검사는 시간이 오래 걸릴 수 있습니다 (수십분~몇시간).\n시작하시겠습니까?", L"확인", MB_YESNO);
            if (res == IDYES) {
                if (!RunDefenderScan(2)) MessageBoxW(hwnd, L"Windows Defender를 찾을 수 없습니다.", L"오류", MB_ICONERROR);
                else WriteLog(L"Windows Defender 전체 검사 실행");
            }
            break;
        }
        case ID_SCAN_START: {
            if (g_scanRunning) { MessageBoxW(hwnd, L"이미 검사가 진행 중입니다.", L"안내", MB_OK); break; }
            int res = MessageBoxW(hwnd, L"드라이브 전체 검사는 파일이 많으면 시간이 오래 걸릴 수 있습니다.\n시작하시겠습니까?", L"확인", MB_YESNO);
            if (res == IDYES) {
                SetWindowTextW(g_lblScanProgress, L"검사 시작 중...");
                HANDLE th = CreateThread(NULL, 0, ScanWorkerProc, NULL, 0, NULL);
                if (th) CloseHandle(th);
            }
            break;
        }
        case ID_SCAN_STOP: {
            if (g_scanRunning) { g_scanCancel = true; WriteLog(L"자체 엔진 검사 중지 요청"); }
            break;
        }
        case ID_SCAN_QUARANTINE: {
            int sel = (int)SendMessageW(g_lstScan, LB_GETCURSEL, 0, 0);
            if (sel == LB_ERR || sel >= (int)g_scanResultPaths.size()) break;
            wstring path = g_scanResultPaths[sel];
            int res = MessageBoxW(hwnd, (L"이 파일을 격리하시겠습니까?\n" + path).c_str(), L"확인", MB_YESNO | MB_ICONWARNING);
            if (res == IDYES) {
                if (QuarantineFile(path)) MessageBoxW(hwnd, L"격리했습니다.", L"완료", MB_OK);
                else MessageBoxW(hwnd, L"격리 실패. 파일이 사용 중이거나 권한이 없을 수 있습니다.", L"오류", MB_ICONERROR);
            }
            break;
        }
        case ID_SCAN_IMPORT_HASH: {
            wchar_t fileName[MAX_PATH] = L"";
            OPENFILENAMEW ofn{}; ofn.lStructSize = sizeof(ofn); ofn.hwndOwner = hwnd;
            ofn.lpstrFilter = L"텍스트 파일\0*.txt\0모든 파일\0*.*\0";
            ofn.lpstrFile = fileName; ofn.nMaxFile = MAX_PATH;
            ofn.lpstrTitle = L"블랙리스트 해시 목록 파일 선택 (한 줄에 SHA-256 해시 하나씩)";
            ofn.Flags = OFN_FILEMUSTEXIST;
            if (GetOpenFileNameW(&ofn)) {
                wifstream f(fileName); wstring line; int count = 0;
                while (getline(f, line)) {
                    size_t s = line.find_first_not_of(L" \t\r\n");
                    if (s == wstring::npos) continue;
                    size_t e = line.find_last_not_of(L" \t\r\n");
                    g_hashBlacklist.push_back(line.substr(s, e - s + 1));
                    count++;
                }
                MessageBoxW(hwnd, (L"해시 " + to_wstring(count) + L"개를 블랙리스트에 추가했습니다.").c_str(), L"완료", MB_OK);
            }
            break;
        }
        case ID_SCAN_UPDATE_FEED: {
            wchar_t keyBuf[256] = L"";
            GetWindowTextW(g_edtMbKey, keyBuf, 256);
            g_mbApiKey = keyBuf;
            {
                wofstream f((g_stateDir + L"\\mbkey.txt").c_str());
                f << g_mbApiKey;
            }
            SetWindowTextW(g_lblScanProgress, L"위협정보 업데이트 중... (잠시 기다려주세요)");
            wstring status;
            bool ok = UpdateThreatIntel(status);
            SetWindowTextW(g_lblScanProgress, status.c_str());
            MessageBoxW(hwnd, status.c_str(), ok ? L"완료" : L"오류", ok ? MB_OK : MB_ICONERROR);
            break;
        }
        case ID_SCAN_IMPORT_PATTERN: {
            wchar_t fileName[MAX_PATH] = L"";
            OPENFILENAMEW ofn{}; ofn.lStructSize = sizeof(ofn); ofn.hwndOwner = hwnd;
            ofn.lpstrFilter = L"텍스트 파일\0*.txt\0모든 파일\0*.*\0";
            ofn.lpstrFile = fileName; ofn.nMaxFile = MAX_PATH;
            ofn.lpstrTitle = L"패턴 목록 파일 선택 (한 줄에 검사할 문자열 하나씩)";
            ofn.Flags = OFN_FILEMUSTEXIST;
            if (GetOpenFileNameW(&ofn)) {
                wifstream f(fileName); wstring line; int count = 0;
                while (getline(f, line)) {
                    size_t s = line.find_first_not_of(L" \t\r\n");
                    if (s == wstring::npos) continue;
                    size_t e = line.find_last_not_of(L" \t\r\n");
                    wstring w = line.substr(s, e - s + 1);
                    g_patternList.push_back(string(w.begin(), w.end()));
                    count++;
                }
                MessageBoxW(hwnd, (L"패턴 " + to_wstring(count) + L"개를 추가했습니다.").c_str(), L"완료", MB_OK);
            }
            break;
        }
        }
        break;
    }

    case WM_SCAN_DONE: {
        MessageBoxW(hwnd, L"자체 엔진 검사가 끝났습니다. 결과 목록을 확인해주세요.", L"완료", MB_OK);
        break;
    }

    case WM_CLOSE: DestroyWindow(hwnd); break;
    case WM_DESTROY: PostQuitMessage(0); break;
    default: return DefWindowProcW(hwnd, msg, wParam, lParam);
    }
    return 0;
}

// ================================================================
// 진입점
// ================================================================
int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, LPWSTR, int nCmdShow) {
    wchar_t userProfile[MAX_PATH];
    DWORD len = GetEnvironmentVariableW(L"USERPROFILE", userProfile, MAX_PATH);
    wstring base = (len > 0) ? wstring(userProfile) : L"C:\\";
    g_baseDir = base + L"\\PC-Guardian";
    g_logDir = g_baseDir + L"\\Logs";
    g_snapDir = g_baseDir + L"\\Snapshots";
    g_evidenceDir = g_baseDir + L"\\Evidence";
    g_stateDir = g_baseDir + L"\\State";
    g_quarantineDir = g_baseDir + L"\\Quarantine";
    EnsureDir(g_baseDir); EnsureDir(g_logDir); EnsureDir(g_snapDir); EnsureDir(g_evidenceDir); EnsureDir(g_stateDir); EnsureDir(g_quarantineDir);
    SeedDefaults();

    LoadState();

    WNDCLASSW wc{};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.lpszClassName = L"PCGuardianWndClass";
    wc.hCursor = LoadCursorW(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    RegisterClassW(&wc);

    g_hMain = CreateWindowExW(0, L"PCGuardianWndClass", L"PC-Guardian",
        WS_OVERLAPPEDWINDOW & ~WS_THICKFRAME & ~WS_MAXIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 1070, 740, NULL, NULL, hInst, NULL);

    ShowWindow(g_hMain, nCmdShow);
    UpdateWindow(g_hMain);

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return 0;
}
