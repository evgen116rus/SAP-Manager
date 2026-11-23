// sap_manager.cpp  -  оконная программа (Win32 GUI)
// Управление SAP GUI 7.70 + SAP Crypto на удалённых ПК.
// Удалённые команды выполняются через pse.exe (переименованный psexec) с ключом -r ps_sap.
// Сборка: см. .github/workflows/build.yml (MSVC, x64).

#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>
#include <winnetwk.h>
#include <wtsapi32.h>
#include <sddl.h>
#include <shlobj.h>
#include <cstdlib>
#include <sstream>
#include <string>
#include <vector>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "version.lib")
#pragma comment(lib, "mpr.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(linker, "\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

using std::wstring;

// ======================= НАСТРОЙКИ =======================
static const wstring DIST_ROOT = L"\\\\ftp\\Distrib\\Soft\\SAP\\SapInstall";
static const wstring SAP770 = DIST_ROOT + L"\\SapInstall770";
static const wstring SAP760 = DIST_ROOT + L"\\OLD\\SapInstall760";
static const wstring SLC    = DIST_ROOT + L"\\SAP_Secure_Login_Client";
static const wstring CRYPTO = DIST_ROOT + L"\\OLD\\SapInstall740\\#\\SapCrypto";
static const wchar_t* PSE_SERVICE = L"ps_sap";                 // pse.exe -r ps_sap
static const wchar_t* REG_MAIN = L"saplogon_options.reg";      // лежит рядом с exe
static const wchar_t* REG_HKCU = L"saplogon_options_HKCU.reg"; // запасной вариант
static const wchar_t* REG_XML = L"set_xml_path.reg";           // запасной вариант (рядом с exe)
static const wchar_t* REMOTE_TMP_REG = L"C:\\Windows\\Temp\\ps_sap_user.reg";
// =========================================================

// ---------- ID элементов и сообщения ----------
enum {
    IDC_PC = 100, IDC_USER, IDC_PASS, IDC_REGUSER,
    IDC_CHK0 = 120,  // 7 флажков: 120..126
    IDC_BTN_INSTALL = 140, IDC_BTN_UNINSTALL, IDC_BTN_CRYPTO, IDC_BTN_REG, IDC_BTN_STATUS,
    IDC_LOG = 160
};
static const int NCOMP = 7;
static const UINT WM_APP_LOG = WM_APP + 1;
static const UINT WM_APP_DONE = WM_APP + 2;
enum Task { T_STATUS, T_INSTALL, T_UNINSTALL, T_CRYPTO, T_REG };

static const wchar_t* COMP_NAMES[NCOMP] = {
    L"SAP GUI 7.70",
    L"PDF Print GUI",
    L"Business Explorer (BE / SapBI)",
    L"SAP Secure Login Client",
    L"SAP Crypto (библиотеки)",
    L"set_xml_path.reg (пути XML) для вошедшего пользователя",
    L"Настройки SAP Logon (reg) для вошедшего пользователя"};

static HWND g_hwnd = nullptr, g_hLog = nullptr;
static HFONT g_font = nullptr, g_monoFont = nullptr;
static wstring g_pc, g_user, g_pass, g_regUser, g_pse, g_exeDir;
static bool g_sel[NCOMP] = {};
static volatile bool g_busy = false;
static Task g_task = T_STATUS;

// ---------- вывод в лог (потокобезопасно) ----------
static void out(const wstring& s) {
    if (!g_hwnd) return;
    PostMessageW(g_hwnd, WM_APP_LOG, 0, (LPARAM) new wstring(s));
}

static void appendLog(const wstring& s) {
    wstring t;
    for (wchar_t c : s) {
        if (c == L'\r') continue;
        if (c == L'\n') t += L"\r\n"; else t += c;
    }
    t += L"\r\n";
    SendMessageW(g_hLog, EM_SETSEL, (WPARAM)-1, (LPARAM)-1);
    SendMessageW(g_hLog, EM_REPLACESEL, FALSE, (LPARAM)t.c_str());
}

static wstring trim(const wstring& s) {
    size_t a = s.find_first_not_of(L" \t\r\n\"");
    if (a == wstring::npos) return L"";
    size_t b = s.find_last_not_of(L" \t\r\n\"");
    return s.substr(a, b - a + 1);
}

static wstring getText(HWND h) {
    int n = GetWindowTextLengthW(h);
    wstring s(n + 1, L'\0');
    GetWindowTextW(h, &s[0], n + 1);
    s.resize(n);
    return s;
}

static bool yn(const wstring& text, bool def = true) {
    return MessageBoxW(g_hwnd, text.c_str(), L"SAP Manager",
                       MB_YESNO | MB_ICONQUESTION | (def ? MB_DEFBUTTON1 : MB_DEFBUTTON2)) == IDYES;
}

// ---------- файлы / пути ----------
static bool exists(const wstring& p) { return GetFileAttributesW(p.c_str()) != INVALID_FILE_ATTRIBUTES; }

static long long fsize(const wstring& p) {
    WIN32_FILE_ATTRIBUTE_DATA d;
    if (!GetFileAttributesExW(p.c_str(), GetFileExInfoStandard, &d)) return -1;
    return ((long long)d.nFileSizeHigh << 32) | d.nFileSizeLow;
}

static wstring fver(const wstring& p) {
    DWORD h = 0;
    DWORD n = GetFileVersionInfoSizeW(p.c_str(), &h);
    if (!n) return L"";
    std::vector<BYTE> b(n);
    if (!GetFileVersionInfoW(p.c_str(), 0, n, b.data())) return L"";
    VS_FIXEDFILEINFO* fi = nullptr;
    UINT l = 0;
    if (!VerQueryValueW(b.data(), L"\\", (LPVOID*)&fi, &l) || !fi) return L"";
    return std::to_wstring(HIWORD(fi->dwFileVersionMS)) + L"." + std::to_wstring(LOWORD(fi->dwFileVersionMS)) + L"." +
           std::to_wstring(HIWORD(fi->dwFileVersionLS)) + L"." + std::to_wstring(LOWORD(fi->dwFileVersionLS));
}

// "C:\xxx" -> "\\PC\C$\xxx"
static wstring adminPath(const wstring& local) { return L"\\\\" + g_pc + L"\\C$\\" + local.substr(3); }

static bool isX64() { return exists(adminPath(L"C:\\Program Files (x86)")); }
static wstring progFiles() { return isX64() ? L"C:\\Program Files (x86)" : L"C:\\Program Files"; }
static wstring guiDir() { return progFiles() + L"\\SAP\\FrontEnd\\SAPgui"; }
static wstring uninstaller() { return progFiles() + L"\\SAP\\SAPsetup\\setup\\NwSapSetup.exe"; }

static wstring conv(UINT cp, const char* d, int n) {
    if (n <= 0) return L"";
    int w = MultiByteToWideChar(cp, 0, d, n, nullptr, 0);
    wstring r(w, L'\0');
    MultiByteToWideChar(cp, 0, d, n, &r[0], w);
    return r;
}

static bool readTextFile(const wstring& p, wstring& t) {
    HANDLE h = CreateFileW(p.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD sz = GetFileSize(h, nullptr), rd = 0;
    std::vector<char> b(sz ? sz : 1);
    BOOL ok = sz ? ReadFile(h, b.data(), sz, &rd, nullptr) : TRUE;
    CloseHandle(h);
    if (!ok) return false;
    if (rd >= 2 && (BYTE)b[0] == 0xFF && (BYTE)b[1] == 0xFE) t.assign((const wchar_t*)(b.data() + 2), (rd - 2) / 2);
    else if (rd >= 3 && (BYTE)b[0] == 0xEF && (BYTE)b[1] == 0xBB && (BYTE)b[2] == 0xBF) t = conv(CP_UTF8, b.data() + 3, (int)rd - 3);
    else t = conv(CP_ACP, b.data(), (int)rd);
    return true;
}

static bool writeUtf16File(const wstring& p, const wstring& t) {
    HANDLE h = CreateFileW(p.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD w = 0;
    const WORD bom = 0xFEFF;
    WriteFile(h, &bom, 2, &w, nullptr);
    WriteFile(h, t.data(), (DWORD)(t.size() * sizeof(wchar_t)), &w, nullptr);
    CloseHandle(h);
    return true;
}

// ---------- pse.exe ----------
static bool findPse() {
    wstring c = g_exeDir + L"pse.exe";
    if (exists(c)) { g_pse = c; return true; }
    wchar_t b[MAX_PATH];
    if (SearchPathW(nullptr, L"pse.exe", nullptr, MAX_PATH, b, nullptr)) { g_pse = b; return true; }
    return false;
}

// Выполняет команду на удалённом ПК: pse.exe \\PC -r ps_sap ... ; вывод идёт в лог
static int runPse(const wstring& remote, bool wait = true) {
    wstring cmd = L"\"" + g_pse + L"\" \\\\" + g_pc + L" -accepteula -r " + PSE_SERVICE + L" -h";
    if (g_user.empty()) cmd += L" -s";
    else cmd += L" -u \"" + g_user + L"\" -p \"" + g_pass + L"\"";
    if (!wait) cmd += L" -d";
    cmd += L" " + remote;
    out(L"  > " + remote);

    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof sa;
    sa.bInheritHandle = TRUE;
    HANDLE rd = nullptr, wr = nullptr;
    if (!CreatePipe(&rd, &wr, &sa, 0)) { out(L"[ОШИБКА] CreatePipe"); return -1; }
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);
    HANDLE nul = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, 0, nullptr);

    STARTUPINFOW si{};
    si.cb = sizeof si;
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdInput = nul;
    si.hStdOutput = wr;
    si.hStdError = wr;
    PROCESS_INFORMATION pi{};
    std::vector<wchar_t> buf(cmd.begin(), cmd.end());
    buf.push_back(0);
    BOOL ok = CreateProcessW(nullptr, buf.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    DWORD err = GetLastError();
    CloseHandle(wr);
    if (nul != INVALID_HANDLE_VALUE) CloseHandle(nul);
    if (!ok) {
        CloseHandle(rd);
        out(L"[ОШИБКА] Не удалось запустить pse.exe, код " + std::to_wstring(err));
        return -1;
    }
    char chunk[4096];
    DWORD n = 0;
    while (ReadFile(rd, chunk, sizeof chunk, &n, nullptr) && n > 0) {
        wstring t = trim(conv(CP_OEMCP, chunk, (int)n));
        if (!t.empty()) out(L"    " + t);
    }
    CloseHandle(rd);
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD ec = 0;
    GetExitCodeProcess(pi.hProcess, &ec);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return wait ? (int)ec : 0;
}

// ---------- подключение ----------
static bool connectPc() {
    if (!g_user.empty()) {
        NETRESOURCEW nr{};
        nr.dwType = RESOURCETYPE_ANY;
        wstring rn = L"\\\\" + g_pc + L"\\IPC$";
        nr.lpRemoteName = (LPWSTR)rn.c_str();
        DWORD r = WNetAddConnection2W(&nr, g_pass.c_str(), g_user.c_str(), 0);
        if (r != NO_ERROR && r != ERROR_SESSION_CREDENTIAL_CONFLICT && r != ERROR_ALREADY_ASSIGNED) {
            out(L"[ОШИБКА] Не удалось подключиться к \\\\" + g_pc + L" с указанной учётной записью, код " + std::to_wstring(r));
            return false;
        }
    }
    if (!exists(L"\\\\" + g_pc + L"\\C$\\")) {
        out(L"[ОШИБКА] Нет доступа к \\\\" + g_pc + L"\\C$ (ПК выключен, нет прав администратора или закрыт SMB).");
        return false;
    }
    return true;
}

static void disconnectPc() {
    if (!g_user.empty() && !g_pc.empty()) WNetCancelConnection2W((L"\\\\" + g_pc + L"\\IPC$").c_str(), 0, TRUE);
}

// ---------- служба удалённого реестра ----------
struct SvcInfo { bool ok = false; DWORD start = 0; DWORD state = 0; };

static SvcInfo queryRemoteRegistry() {
    SvcInfo r;
    SC_HANDLE scm = OpenSCManagerW((L"\\\\" + g_pc).c_str(), nullptr, SC_MANAGER_CONNECT);
    if (!scm) return r;
    SC_HANDLE s = OpenServiceW(scm, L"RemoteRegistry", SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS);
    if (s) {
        std::vector<BYTE> b(8192);
        DWORD need = 0;
        if (QueryServiceConfigW(s, (LPQUERY_SERVICE_CONFIGW)b.data(), (DWORD)b.size(), &need))
            r.start = ((LPQUERY_SERVICE_CONFIGW)b.data())->dwStartType;
        SERVICE_STATUS st{};
        if (QueryServiceStatus(s, &st)) { r.state = st.dwCurrentState; r.ok = true; }
        CloseServiceHandle(s);
    }
    CloseServiceHandle(scm);
    return r;
}

static wstring startName(DWORD t) {
    switch (t) {
        case SERVICE_AUTO_START: return L"автоматически";
        case SERVICE_DEMAND_START: return L"вручную";
        case SERVICE_DISABLED: return L"отключена";
        default: return L"?";
    }
}

static bool ensureRemoteRegistry() {
    SvcInfo s = queryRemoteRegistry();
    if (!s.ok || s.start != SERVICE_AUTO_START) {
        out(L"Служба удалённого реестра: ставлю запуск \"Автоматически\"...");
        runPse(L"sc config RemoteRegistry start= auto");
    }
    s = queryRemoteRegistry();
    if (!s.ok || s.state != SERVICE_RUNNING) {
        out(L"Запускаю службу удалённого реестра...");
        runPse(L"sc start RemoteRegistry");
        for (int i = 0; i < 15; i++) {
            Sleep(1000);
            s = queryRemoteRegistry();
            if (s.ok && s.state == SERVICE_RUNNING) break;
        }
    }
    bool ok = s.ok && s.state == SERVICE_RUNNING;
    out(ok ? L"[OK] Служба удалённого реестра запущена." : L"[ВНИМАНИЕ] Служба удалённого реестра не запущена.");
    return ok;
}

static bool regKeyExists(const wstring& sub) {
    HKEY root = nullptr;
    if (RegConnectRegistryW((L"\\\\" + g_pc).c_str(), HKEY_USERS, &root) != ERROR_SUCCESS) return false;
    HKEY k = nullptr;
    LONG e = RegOpenKeyExW(root, sub.c_str(), 0, KEY_READ, &k);
    if (k) RegCloseKey(k);
    RegCloseKey(root);
    return e == ERROR_SUCCESS;
}

// ---------- вошедший пользователь ----------
struct Sess { wstring dom, user; DWORD id = 0; };

static bool listUsers(std::vector<Sess>& v) {
    HANDLE h = WTSOpenServerW((LPWSTR)g_pc.c_str());
    if (!h) return false;
    PWTS_SESSION_INFOW si = nullptr;
    DWORD n = 0;
    if (!WTSEnumerateSessionsW(h, 0, 1, &si, &n)) { WTSCloseServer(h); return false; }
    for (DWORD i = 0; i < n; i++) {
        if (si[i].State != WTSActive && si[i].State != WTSDisconnected) continue;
        LPWSTR u = nullptr, d = nullptr;
        DWORD l = 0;
        WTSQuerySessionInformationW(h, si[i].SessionId, WTSUserName, &u, &l);
        WTSQuerySessionInformationW(h, si[i].SessionId, WTSDomainName, &d, &l);
        if (u && *u) {
            Sess s;
            s.user = u;
            s.dom = d ? d : L"";
            s.id = si[i].SessionId;
            v.push_back(s);
        }
        if (u) WTSFreeMemory(u);
        if (d) WTSFreeMemory(d);
    }
    WTSFreeMemory(si);
    WTSCloseServer(h);
    return true;
}

static bool accountSid(const wstring& acc, wstring& sidStr) {
    DWORD sn = 0, dn = 0;
    SID_NAME_USE use;
    LookupAccountNameW(g_pc.c_str(), acc.c_str(), nullptr, &sn, nullptr, &dn, &use);
    if (!sn) return false;
    std::vector<BYTE> sid(sn);
    std::vector<wchar_t> dom(dn ? dn : 1);
    if (!LookupAccountNameW(g_pc.c_str(), acc.c_str(), sid.data(), &sn, dom.data(), &dn, &use)) return false;
    LPWSTR s = nullptr;
    if (!ConvertSidToStringSidW(sid.data(), &s)) return false;
    sidStr = s;
    LocalFree(s);
    return true;
}

// Берёт пользователя из поля "Пользователь для reg" либо определяет вошедшего
static bool pickUser(wstring& acc, wstring& sid) {
    if (!g_regUser.empty()) {
        acc = g_regUser;
    } else {
        std::vector<Sess> v;
        bool ok = listUsers(v);
        if (!ok || v.empty()) {
            out(L"[ОШИБКА] Не удалось определить вошедшего пользователя. Введите DOMAIN\\user в поле \"Пользователь для reg\".");
            return false;
        }
        if (v.size() == 1) acc = v[0].dom + L"\\" + v[0].user;
        else {
            bool chosen = false;
            for (auto& s : v) {
                wstring a = s.dom + L"\\" + s.user;
                int r = MessageBoxW(g_hwnd, (L"Применить настройки для " + a + L" (сессия " + std::to_wstring(s.id) + L")?").c_str(),
                                    L"Несколько сессий", MB_YESNOCANCEL | MB_ICONQUESTION);
                if (r == IDCANCEL) return false;
                if (r == IDYES) { acc = a; chosen = true; break; }
            }
            if (!chosen) return false;
        }
    }
    if (!accountSid(acc, sid)) {
        out(L"[ОШИБКА] Не удалось получить SID для " + acc);
        return false;
    }
    return true;
}

// ---------- reg-файлы ----------
static wstring rewriteReg(const wstring& t, const wstring& sid) {
    const wstring hkcu = L"HKEY_CURRENT_USER";
    wstring res, line;
    std::wistringstream ss(t);
    while (std::getline(ss, line)) {
        if (!line.empty() && line.back() == L'\r') line.pop_back();
        if (!line.empty() && line[0] == L'[') {
            size_t p = (line.size() > 1 && line[1] == L'-') ? 2 : 1;
            if (line.compare(p, hkcu.size(), hkcu) == 0) line.replace(p, hkcu.size(), L"HKEY_USERS\\" + sid);
        }
        res += line + L"\r\n";
    }
    return res;
}

// Первый ключ HKEY_CURRENT_USER из reg-файла (для проверки результата)
static wstring firstHkcuKey(const wstring& t) {
    const wstring pre = L"[HKEY_CURRENT_USER\\";
    std::wistringstream ss(t);
    wstring line;
    while (std::getline(ss, line)) {
        if (line.compare(0, pre.size(), pre) == 0) {
            size_t e = line.find(L']');
            return line.substr(pre.size(), e == wstring::npos ? wstring::npos : e - pre.size());
        }
    }
    return L"";
}

// Импортирует один reg-файл в реестр пользователя с заданным SID
static bool importRegForUser(const wstring& src, const wstring& sid, bool rr) {
    out(L"Reg-файл: " + src);
    wstring text;
    if (!readTextFile(src, text)) { out(L"[ОШИБКА] Не удалось прочитать " + src); return false; }

    wchar_t tmp[MAX_PATH];
    GetTempPathW(MAX_PATH, tmp);
    wstring local = wstring(tmp) + L"ps_sap_user.reg";
    if (!writeUtf16File(local, rewriteReg(text, sid))) { out(L"[ОШИБКА] Не удалось создать временный reg-файл."); return false; }

    wstring remoteShare = adminPath(REMOTE_TMP_REG);
    if (!CopyFileW(local.c_str(), remoteShare.c_str(), FALSE)) {
        out(L"[ОШИБКА] Не удалось скопировать reg на ПК, код " + std::to_wstring(GetLastError()));
        DeleteFileW(local.c_str());
        return false;
    }
    DeleteFileW(local.c_str());

    int rc = runPse(wstring(L"reg import ") + REMOTE_TMP_REG);
    DeleteFileW(remoteShare.c_str());
    if (rc != 0) { out(L"[ОШИБКА] reg import завершился с кодом " + std::to_wstring(rc)); return false; }

    wstring key = firstHkcuKey(text);
    if (rr && !key.empty()) {
        bool ok = regKeyExists(sid + L"\\" + key);
        out(ok ? L"[OK] Применено, ключ найден: HKEY_USERS\\<SID>\\" + key
               : L"[ВНИМАНИЕ] Импорт выполнен, но ключ не найден: " + key);
    } else {
        out(L"[OK] Импорт выполнен.");
    }
    return true;
}

// Применяет reg-файлы к реестру ВОШЕДШЕГО пользователя удалённого ПК
static void applyRegFiles(const std::vector<wstring>& files) {
    out(L"=== Применение reg-файлов для вошедшего пользователя ===");
    bool rr = ensureRemoteRegistry();

    wstring acc, sid;
    if (!pickUser(acc, sid)) return;
    out(L"Пользователь: " + acc + L"  SID: " + sid);

    if (rr && !regKeyExists(sid)) {
        out(L"[ОШИБКА] Профиль пользователя не загружен в HKEY_USERS на " + g_pc + L" (пользователь не вошёл?).");
        return;
    }
    for (auto& f : files) importRegForUser(f, sid, rr);
}

static wstring optionsRegPath() {
    wstring p = g_exeDir + REG_MAIN;
    if (!exists(p)) p = g_exeDir + REG_HKCU;
    return p;
}

static wstring xmlRegPath() {
    wstring p = SAP760 + L"\\#\\set_xml_path.reg";
    if (!exists(p)) {
        wstring q = g_exeDir + REG_XML;
        if (exists(q)) return q;
    }
    return p;
}

// ---------- SAP Crypto ----------
struct CF { wstring name, src; };

static std::vector<CF> cryptoFiles() {
    wstring arch = isX64() ? L"\\x64" : L"\\x86";
    std::vector<CF> v;
    v.push_back({L"sapcrypto.dll", CRYPTO + L"\\sapcrypto.dll"});
    v.push_back({L"sapgenpse.exe", CRYPTO + L"\\sapgenpse.exe"});
    v.push_back({L"slcryptokernel.dll", CRYPTO + L"\\slcryptokernel.dll"});
    v.push_back({L"ssfrfc.ini", CRYPTO + arch + L"\\ssfrfc.ini"});
    return v;
}

static int checkCrypto(bool verbose) {
    wstring dir = adminPath(guiDir());
    int bad = 0;
    for (auto& f : cryptoFiles()) {
        wstring dst = dir + L"\\" + f.name;
        long long s = fsize(dst);
        wstring st;
        if (s < 0) { st = L"[НЕТ] "; bad++; }
        else {
            long long ss = fsize(f.src);
            if (ss >= 0 && ss != s) { st = L"[ОТЛИЧАЕТСЯ] "; bad++; }
            else st = L"[OK] ";
        }
        if (verbose) out(L"  " + st + f.name + (s >= 0 ? L"  " + std::to_wstring(s) + L" байт" : wstring()));
    }
    return bad;
}

static bool copyCrypto() {
    out(L"=== Копирование SAP Crypto ===");
    wstring dir = adminPath(guiDir());
    if (!exists(dir)) {
        int r = SHCreateDirectoryExW(nullptr, dir.c_str(), nullptr);
        if (r != ERROR_SUCCESS && r != ERROR_ALREADY_EXISTS) { out(L"[ОШИБКА] Не удалось создать " + dir); return false; }
    }
    bool all = true;
    for (auto& f : cryptoFiles()) {
        if (CopyFileW(f.src.c_str(), (dir + L"\\" + f.name).c_str(), FALSE)) out(L"  [OK] " + f.name);
        else { out(L"  [ОШИБКА] " + f.name + L", код " + std::to_wstring(GetLastError())); all = false; }
    }
    return all;
}

// ---------- статус ----------
static bool sapInstalled() { return exists(adminPath(guiDir() + L"\\saplogon.exe")); }

static void showStatus() {
    out(L"=== Статус " + g_pc + L" ===");
    out(wstring(L"Разрядность ОС: ") + (isX64() ? L"64-bit" : L"32-bit"));

    wstring exe = adminPath(guiDir() + L"\\saplogon.exe");
    if (exists(exe)) {
        wstring v = fver(exe);
        out(L"[OK] SAP GUI установлен" + (v.empty() ? wstring() : L", версия " + v));
    } else out(L"[НЕТ] SAP GUI не установлен (нет saplogon.exe)");
    out(exists(adminPath(uninstaller())) ? L"[OK] Найден NwSapSetup.exe (деинсталлятор)" : L"[НЕТ] NwSapSetup.exe не найден");

    out(L"Компоненты SAP Crypto:");
    int bad = checkCrypto(true);
    out(bad == 0 ? wstring(L"[OK] Все компоненты Crypto на месте.") : L"[ВНИМАНИЕ] Проблемных компонентов: " + std::to_wstring(bad));

    SvcInfo s = queryRemoteRegistry();
    if (s.ok) out(L"Удалённый реестр: " + startName(s.start) + L", " + (s.state == SERVICE_RUNNING ? L"работает" : L"остановлена"));
    else out(L"Удалённый реестр: состояние не удалось получить");

    std::vector<Sess> v;
    if (listUsers(v) && !v.empty()) {
        for (auto& u : v) out(L"Вошедший пользователь: " + u.dom + L"\\" + u.user);
    } else out(L"Вошедший пользователь: не обнаружен");
}

// ---------- установка / удаление ----------
static void doInstall() {
    out(L"=== Установка SAP на " + g_pc + L" ===");
    bool any = false;
    for (int i = 0; i < NCOMP; i++) any = any || g_sel[i];
    if (!any) { out(L"Не выбран ни один компонент."); return; }

    wstring list;
    for (int i = 0; i < NCOMP; i++) if (g_sel[i]) list += L"\n  - " + wstring(COMP_NAMES[i]);
    if (!yn(L"Установить на " + g_pc + L":" + list + L"\n\nПродолжить?")) { out(L"Отменено."); return; }

    bool installed = sapInstalled();
    if ((g_sel[1] || g_sel[2]) && !g_sel[0] && !installed)
        out(L"[ВНИМАНИЕ] SAP GUI на ПК не установлен, а PDF Print / BE ставятся поверх него.");
    if (g_sel[0] && installed && !yn(L"SAP GUI уже установлен. Переустановить/обновить?", false)) g_sel[0] = false;

    if (!exists(SAP770 + L"\\Setup\\NwSapSetup.exe"))
        out(L"[ВНИМАНИЕ] Дистрибутив не виден с этого ПК: " + SAP770 + L" (на удалённом ПК он может быть доступен)");

    struct Step { int idx; const wchar_t* title; wstring cmd; };
    std::vector<Step> steps;
    steps.push_back({0, L"SAP GUI 7.70", SAP770 + L"\\Setup\\NwSapSetup.exe /Silent /Package=SapGui770 /noDLG"});
    steps.push_back({1, L"PDF Print GUI", SAP770 + L"\\Setup\\NwSapSetup.exe /Silent /Product=PdfPrintGui /noDLG"});
    steps.push_back({2, L"Business Explorer", SAP770 + L"\\Setup\\NwSapSetup.exe /Silent /Product=SapBI /noDLG"});
    steps.push_back({3, L"SAP Secure Login Client", SLC + L"\\Setup\\NwSapSetup.exe /Silent /Product=SLC /noDLG"});
    for (auto& s : steps) {
        if (!g_sel[s.idx]) continue;
        out(L"[установка] " + wstring(s.title));
        int rc = runPse(s.cmd);
        if (rc != 0) out(L"  [ВНИМАНИЕ] код возврата " + std::to_wstring(rc) + L" (3010 = нужна перезагрузка)");
    }
    if (g_sel[4]) copyCrypto();
    if (g_sel[0] && exists(SAP770 + L"\\CheckFileServices.exe")) {
        out(L"Запуск CheckFileServices.exe (без ожидания)...");
        runPse(SAP770 + L"\\CheckFileServices.exe", false);
    }
    std::vector<wstring> regs;
    if (g_sel[5]) regs.push_back(xmlRegPath());
    if (g_sel[6]) regs.push_back(optionsRegPath());
    if (!regs.empty()) applyRegFiles(regs);
    showStatus();
}

static void doUninstall() {
    out(L"=== Удаление SAP GUI на " + g_pc + L" ===");
    if (!yn(L"Удалить SAP GUI и папку SAP на " + g_pc + L"?", false)) { out(L"Отменено."); return; }
    wstring u = L"\"" + uninstaller() + L"\"";
    if (exists(adminPath(uninstaller()))) {
        out(L"[1/3] SapBI");
        runPse(u + L" /Product=SapBI /Uninstall /Silent /NoDLG");
        out(L"[2/3] SAP GUI и PDF Print");
        runPse(u + L" /Uninstall /Product=PdfPrintGui+SCRIPTED+SCE+SAPDTS+KW+GUIISHMED+JNet+CALSYNC+SAPGUI /TitleComponent:SAPGUI /IgnoreMissingProducts /Silent /NoDLG");
        out(L"[3/3] SAP Secure Login Client");
        runPse(u + L" /Product=SLC /Uninstall /Silent /NoDLG");
    } else out(L"Деинсталлятор не найден, перехожу к очистке папок.");
    out(L"Очистка остаточных каталогов...");
    runPse(L"cmd /c rd /s /q \"" + progFiles() + L"\\SAP\"");
    showStatus();
}

static void doCrypto() {
    out(L"=== SAP Crypto на " + g_pc + L" ===");
    int bad = checkCrypto(true);
    if (bad == 0) { out(L"[OK] Все компоненты на месте."); return; }
    if (yn(L"Найдено проблемных компонентов: " + std::to_wstring(bad) + L". Скопировать/обновить?")) {
        copyCrypto();
        checkCrypto(true);
    }
}

// ---------- рабочий поток ----------
static DWORD WINAPI worker(LPVOID) {
    if (connectPc()) {
        switch (g_task) {
            case T_STATUS: showStatus(); break;
            case T_INSTALL: doInstall(); break;
            case T_UNINSTALL: doUninstall(); break;
            case T_CRYPTO: doCrypto(); break;
            case T_REG: { std::vector<wstring> regs; regs.push_back(xmlRegPath()); regs.push_back(optionsRegPath()); applyRegFiles(regs); break; }
        }
    }
    out(L"--- готово ---\n");
    PostMessageW(g_hwnd, WM_APP_DONE, 0, 0);
    return 0;
}

static void setButtons(bool enabled) {
    for (int id = IDC_BTN_INSTALL; id <= IDC_BTN_STATUS; id++) EnableWindow(GetDlgItem(g_hwnd, id), enabled);
}

static void startTask(Task t) {
    if (g_busy) return;
    wstring pc = trim(getText(GetDlgItem(g_hwnd, IDC_PC)));
    while (!pc.empty() && pc[0] == L'\\') pc.erase(0, 1);
    if (pc.empty()) {
        MessageBoxW(g_hwnd, L"Введите имя компьютера.", L"SAP Manager", MB_OK | MB_ICONWARNING);
        SetFocus(GetDlgItem(g_hwnd, IDC_PC));
        return;
    }
    if (g_pse.empty() && !findPse()) {
        MessageBoxW(g_hwnd, L"pse.exe не найден. Положите его рядом с программой или в PATH.", L"SAP Manager", MB_OK | MB_ICONERROR);
        return;
    }
    disconnectPc();
    g_pc = pc;
    g_user = trim(getText(GetDlgItem(g_hwnd, IDC_USER)));
    g_pass = getText(GetDlgItem(g_hwnd, IDC_PASS));
    g_regUser = trim(getText(GetDlgItem(g_hwnd, IDC_REGUSER)));
    for (int i = 0; i < NCOMP; i++) g_sel[i] = Button_GetCheck(GetDlgItem(g_hwnd, IDC_CHK0 + i)) == BST_CHECKED;
    g_task = t;
    g_busy = true;
    setButtons(false);
    HANDLE h = CreateThread(nullptr, 0, worker, nullptr, 0, nullptr);
    if (h) CloseHandle(h);
    else { g_busy = false; setButtons(true); }
}

// ---------- окно ----------
static HWND mk(const wchar_t* cls, const wchar_t* text, DWORD style, int x, int y, int w, int h, int id, DWORD ex = 0) {
    return CreateWindowExW(ex, cls, text, WS_CHILD | WS_VISIBLE | style, x, y, w, h, g_hwnd, (HMENU)(INT_PTR)id,
                           GetModuleHandleW(nullptr), nullptr);
}

static BOOL CALLBACK setFontProc(HWND h, LPARAM f) {
    SendMessageW(h, WM_SETFONT, (WPARAM)f, TRUE);
    return TRUE;
}

static void createControls() {
    mk(L"STATIC", L"Компьютер:", 0, 10, 14, 90, 20, -1);
    mk(L"EDIT", L"", WS_TABSTOP | ES_AUTOHSCROLL, 105, 10, 200, 24, IDC_PC, WS_EX_CLIENTEDGE);
    mk(L"STATIC", L"Учётная запись:", 0, 320, 14, 100, 20, -1);
    mk(L"EDIT", L"", WS_TABSTOP | ES_AUTOHSCROLL, 425, 10, 150, 24, IDC_USER, WS_EX_CLIENTEDGE);
    mk(L"STATIC", L"Пароль:", 0, 585, 14, 55, 20, -1);
    mk(L"EDIT", L"", WS_TABSTOP | ES_AUTOHSCROLL | ES_PASSWORD, 645, 10, 110, 24, IDC_PASS, WS_EX_CLIENTEDGE);

    mk(L"STATIC", L"Пользователь для reg:", 0, 10, 46, 135, 20, -1);
    mk(L"EDIT", L"", WS_TABSTOP | ES_AUTOHSCROLL, 150, 42, 200, 24, IDC_REGUSER, WS_EX_CLIENTEDGE);
    mk(L"STATIC", L"DOMAIN\\user; пусто = вошедший пользователь определяется сам", 0, 360, 46, 395, 20, -1);

    mk(L"BUTTON", L"Компоненты установки", BS_GROUPBOX, 10, 76, 745, 118, -1);
    for (int i = 0; i < NCOMP; i++) {
        int col = i < 4 ? 0 : 1;
        int row = i < 4 ? i : i - 4;
        HWND c = mk(L"BUTTON", COMP_NAMES[i], WS_TABSTOP | BS_AUTOCHECKBOX, col ? 390 : 25, 96 + row * 22, col ? 355 : 350, 20, IDC_CHK0 + i);
        Button_SetCheck(c, BST_CHECKED);
    }

    mk(L"BUTTON", L"Установить выбранное", WS_TABSTOP | BS_DEFPUSHBUTTON, 10, 202, 170, 30, IDC_BTN_INSTALL);
    mk(L"BUTTON", L"Удалить SAP", WS_TABSTOP | BS_PUSHBUTTON, 190, 202, 110, 30, IDC_BTN_UNINSTALL);
    mk(L"BUTTON", L"Crypto: проверить", WS_TABSTOP | BS_PUSHBUTTON, 310, 202, 150, 30, IDC_BTN_CRYPTO);
    mk(L"BUTTON", L"Reg пользователю", WS_TABSTOP | BS_PUSHBUTTON, 470, 202, 150, 30, IDC_BTN_REG);
    mk(L"BUTTON", L"Статус", WS_TABSTOP | BS_PUSHBUTTON, 630, 202, 125, 30, IDC_BTN_STATUS);

    g_hLog = mk(L"EDIT", L"", WS_VSCROLL | WS_HSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | ES_AUTOHSCROLL,
                10, 242, 745, 300, IDC_LOG, WS_EX_CLIENTEDGE);
    SendMessageW(g_hLog, EM_SETLIMITTEXT, 0x7FFFFFF, 0);

    NONCLIENTMETRICSW ncm{};
    ncm.cbSize = sizeof ncm;
    SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof ncm, &ncm, 0);
    g_font = CreateFontIndirectW(&ncm.lfMessageFont);
    EnumChildWindows(g_hwnd, setFontProc, (LPARAM)g_font);
    g_monoFont = CreateFontW(-14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                             CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, FIXED_PITCH | FF_MODERN, L"Consolas");
    SendMessageW(g_hLog, WM_SETFONT, (WPARAM)g_monoFont, TRUE);
}

static LRESULT CALLBACK wndProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    switch (m) {
        case WM_CREATE:
            g_hwnd = h;
            createControls();
            if (findPse()) out(L"pse.exe: " + g_pse);
            else out(L"[ВНИМАНИЕ] pse.exe не найден (положите рядом с программой или в PATH).");
            out(L"Введите имя компьютера и нажмите \"Статус\" или выберите действие.\n");
            return 0;
        case WM_SIZE: {
            int cw = LOWORD(l), ch = HIWORD(l);
            if (g_hLog) MoveWindow(g_hLog, 10, 242, cw - 20 > 100 ? cw - 20 : 100, ch - 252 > 60 ? ch - 252 : 60, TRUE);
            return 0;
        }
        case WM_GETMINMAXINFO: {
            MINMAXINFO* mi = (MINMAXINFO*)l;
            mi->ptMinTrackSize.x = 800;
            mi->ptMinTrackSize.y = 480;
            return 0;
        }
        case WM_COMMAND:
            switch (LOWORD(w)) {
                case IDC_BTN_INSTALL: startTask(T_INSTALL); break;
                case IDC_BTN_UNINSTALL: startTask(T_UNINSTALL); break;
                case IDC_BTN_CRYPTO: startTask(T_CRYPTO); break;
                case IDC_BTN_REG: startTask(T_REG); break;
                case IDC_BTN_STATUS: startTask(T_STATUS); break;
            }
            return 0;
        case WM_APP_LOG: {
            wstring* s = (wstring*)l;
            appendLog(*s);
            delete s;
            return 0;
        }
        case WM_APP_DONE:
            g_busy = false;
            setButtons(true);
            return 0;
        case WM_CLOSE:
            if (g_busy && MessageBoxW(h, L"Операция ещё выполняется. Закрыть программу?", L"SAP Manager",
                                      MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) != IDYES)
                return 0;
            DestroyWindow(h);
            return 0;
        case WM_DESTROY:
            disconnectPc();
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProcW(h, m, w, l);
}

int WINAPI wWinMain(HINSTANCE hi, HINSTANCE, LPWSTR, int show) {
    INITCOMMONCONTROLSEX ic{sizeof ic, ICC_STANDARD_CLASSES};
    InitCommonControlsEx(&ic);

    wchar_t me[MAX_PATH];
    GetModuleFileNameW(nullptr, me, MAX_PATH);
    g_exeDir = me;
    g_exeDir = g_exeDir.substr(0, g_exeDir.find_last_of(L'\\') + 1);

    WNDCLASSEXW wc{};
    wc.cbSize = sizeof wc;
    wc.lpfnWndProc = wndProc;
    wc.hInstance = hi;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = L"SapManagerWnd";
    RegisterClassExW(&wc);

    RECT r = {0, 0, 765, 580};
    AdjustWindowRect(&r, WS_OVERLAPPEDWINDOW, FALSE);
    HWND hw = CreateWindowExW(0, wc.lpszClassName, L"SAP Manager — установка SAP GUI + Crypto (pse -r ps_sap)",
                              WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, r.right - r.left, r.bottom - r.top,
                              nullptr, nullptr, hi, nullptr);
    if (!hw) return 1;
    ShowWindow(hw, show);
    UpdateWindow(hw);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        if (!IsDialogMessageW(hw, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    return (int)msg.wParam;
}
