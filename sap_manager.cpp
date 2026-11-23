// sap_manager.cpp
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
#include <winnetwk.h>
#include <wtsapi32.h>
#include <sddl.h>
#include <shlobj.h>
#include <conio.h>
#include <fcntl.h>
#include <io.h>
#include <cwctype>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "version.lib")
#pragma comment(lib, "mpr.lib")
#pragma comment(lib, "shell32.lib")

using std::wstring;
using std::wcout;

// ======================= НАСТРОЙКИ =======================
static const wstring DIST_ROOT = L"\\\\ftp\\Distrib\\Soft\\SAP\\SapInstall";
static const wstring SAP770 = DIST_ROOT + L"\\SapInstall770";
static const wstring SAP760 = DIST_ROOT + L"\\OLD\\SapInstall760";
static const wstring SLC    = DIST_ROOT + L"\\SAP_Secure_Login_Client";
static const wstring CRYPTO = DIST_ROOT + L"\\OLD\\SapInstall740\\#\\SapCrypto";
static const wchar_t* PSE_SERVICE = L"ps_sap";                 // pse.exe -r ps_sap
static const wchar_t* REG_MAIN = L"saplogon_options.reg";      // лежит рядом с exe
static const wchar_t* REG_HKCU = L"saplogon_options_HKCU.reg"; // запасной вариант
static const wchar_t* REMOTE_TMP_REG = L"C:\\Windows\\Temp\\ps_sap_user.reg";
// =========================================================

static wstring g_pc, g_user, g_pass, g_pse, g_exeDir;

// ---------- ввод / вывод ----------
static void out(const wstring& s) { wcout << s << std::endl; }

static wstring trim(const wstring& s) {
    size_t a = s.find_first_not_of(L" \t\r\n\"");
    if (a == wstring::npos) return L"";
    size_t b = s.find_last_not_of(L" \t\r\n\"");
    return s.substr(a, b - a + 1);
}

static wstring ask(const wstring& prompt) {
    wcout << prompt << std::flush;
    wstring s;
    if (!std::getline(std::wcin, s)) std::exit(0);
    return trim(s);
}

static bool yn(const wstring& prompt, bool def) {
    wstring a = ask(prompt + (def ? L" [Y/n]: " : L" [y/N]: "));
    if (a.empty()) return def;
    wchar_t c = a[0];
    return c == L'y' || c == L'Y' || c == L'д' || c == L'Д' || c == L'1';
}

static wstring askSecret(const wstring& prompt) {
    wcout << prompt << std::flush;
    wstring s;
    for (;;) {
        wint_t c = _getwch();
        if (c == L'\r' || c == L'\n') break;
        if (c == 0 || c == 0xE0) { _getwch(); continue; }
        if (c == 8) { if (!s.empty()) s.pop_back(); continue; }
        s.push_back((wchar_t)c);
    }
    wcout << std::endl;
    return s;
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
    std::vector<char> b(sz);
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

// Выполняет команду на удалённом ПК: pse.exe \\PC -r ps_sap ...
static int runPse(const wstring& remote, bool wait = true) {
    wstring cmd = L"\"" + g_pse + L"\" \\\\" + g_pc + L" -accepteula -r " + PSE_SERVICE + L" -h";
    if (g_user.empty()) cmd += L" -s";
    else cmd += L" -u \"" + g_user + L"\" -p \"" + g_pass + L"\"";
    if (!wait) cmd += L" -d";
    cmd += L" " + remote;
    out(L"  > " + remote);
    std::vector<wchar_t> buf(cmd.begin(), cmd.end());
    buf.push_back(0);
    STARTUPINFOW si{};
    si.cb = sizeof si;
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(nullptr, buf.data(), nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) {
        out(L"[ОШИБКА] Не удалось запустить pse.exe, код " + std::to_wstring(GetLastError()));
        return -1;
    }
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
        if (r != NO_ERROR && r != ERROR_SESSION_CREDENTIAL_CONFLICT) {
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

static bool pickUser(wstring& acc, wstring& sid) {
    std::vector<Sess> v;
    bool ok = listUsers(v);
    if (!ok || v.empty()) {
        out(L"Не удалось определить вошедшего пользователя автоматически.");
        acc = ask(L"Введите учётную запись в виде DOMAIN\\user (Enter — отмена): ");
        if (acc.empty()) return false;
    } else if (v.size() == 1) {
        acc = v[0].dom + L"\\" + v[0].user;
    } else {
        out(L"Найдено несколько сессий:");
        for (size_t i = 0; i < v.size(); i++)
            out(L"  " + std::to_wstring(i + 1) + L") " + v[i].dom + L"\\" + v[i].user + L" (сессия " + std::to_wstring(v[i].id) + L")");
        wstring a = ask(L"Номер пользователя: ");
        size_t k = (size_t)_wtoi(a.c_str());
        if (k < 1 || k > v.size()) return false;
        acc = v[k - 1].dom + L"\\" + v[k - 1].user;
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

// Добавляет reg-файл в реестр ВОШЕДШЕГО пользователя удалённого ПК
static void applyRegToUser() {
    out(L"\n=== Применение reg-файла для вошедшего пользователя ===");
    bool rr = ensureRemoteRegistry();

    wstring acc, sid;
    if (!pickUser(acc, sid)) return;
    out(L"Пользователь: " + acc + L"\nSID: " + sid);

    if (rr && !regKeyExists(sid)) {
        out(L"[ОШИБКА] Профиль пользователя не загружен в HKEY_USERS на " + g_pc + L" (пользователь не вошёл?).");
        return;
    }

    wstring src = g_exeDir + REG_MAIN;
    if (!exists(src)) src = g_exeDir + REG_HKCU;
    wstring text;
    if (!readTextFile(src, text)) {
        out(L"[ОШИБКА] Не найден reg-файл рядом с программой: " + wstring(REG_MAIN) + L" / " + REG_HKCU);
        return;
    }
    out(L"Reg-файл: " + src);

    wchar_t tmp[MAX_PATH];
    GetTempPathW(MAX_PATH, tmp);
    wstring local = wstring(tmp) + L"ps_sap_user.reg";
    if (!writeUtf16File(local, rewriteReg(text, sid))) { out(L"[ОШИБКА] Не удалось создать временный reg-файл."); return; }

    wstring remoteShare = adminPath(REMOTE_TMP_REG);
    if (!CopyFileW(local.c_str(), remoteShare.c_str(), FALSE)) {
        out(L"[ОШИБКА] Не удалось скопировать reg на ПК, код " + std::to_wstring(GetLastError()));
        DeleteFileW(local.c_str());
        return;
    }
    DeleteFileW(local.c_str());

    int rc = runPse(wstring(L"reg import ") + REMOTE_TMP_REG);
    DeleteFileW(remoteShare.c_str());
    if (rc != 0) { out(L"[ОШИБКА] reg import завершился с кодом " + std::to_wstring(rc)); return; }

    if (rr) {
        bool ok = regKeyExists(sid + L"\\Software\\SAP\\SAPLogon\\Settings");
        out(ok ? L"[OK] Настройки SAP Logon применены (ключ найден в HKEY_USERS\\<SID>)."
               : L"[ВНИМАНИЕ] Импорт выполнен, но ключ SAPLogon\\Settings не найден.");
    } else {
        out(L"[OK] Импорт выполнен (проверка через удалённый реестр недоступна).");
    }
}

// ---------- SAP Crypto ----------
struct CF { wstring name, src; };

static std::vector<CF> cryptoFiles() {
    wstring arch = isX64() ? L"\\x64" : L"\\x86";
    return { {L"sapcrypto.dll", CRYPTO + L"\\sapcrypto.dll"},
             {L"sapgenpse.exe", CRYPTO + L"\\sapgenpse.exe"},
             {L"slcryptokernel.dll", CRYPTO + L"\\slcryptokernel.dll"},
             {L"ssfrfc.ini", CRYPTO + arch + L"\\ssfrfc.ini"} };
}

static int checkCrypto(bool verbose) {
    wstring dir = adminPath(guiDir());
    int bad = 0;
    for (auto& f : cryptoFiles()) {
        wstring dst = dir + L"\\" + f.name;
        long long s = fsize(dst);
        wstring st;
        if (s < 0) { st = L"[НЕТ]      "; bad++; }
        else {
            long long ss = fsize(f.src);
            if (ss >= 0 && ss != s) { st = L"[ОТЛИЧАЕТСЯ] "; bad++; }
            else st = L"[OK]       ";
        }
        if (verbose) out(L"  " + st + f.name + (s >= 0 ? L"  " + std::to_wstring(s) + L" байт" : L""));
    }
    return bad;
}

static bool copyCrypto() {
    out(L"\n=== Копирование SAP Crypto ===");
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
    out(L"\n=== Статус " + g_pc + L" ===");
    out(wstring(L"Разрядность ОС: ") + (isX64() ? L"64-bit" : L"32-bit"));

    wstring exe = adminPath(guiDir() + L"\\saplogon.exe");
    if (exists(exe)) {
        wstring v = fver(exe);
        out(L"[OK] SAP GUI установлен" + (v.empty() ? L"" : L", версия " + v));
    } else out(L"[НЕТ] SAP GUI не установлен (нет saplogon.exe)");
    out(exists(adminPath(uninstaller())) ? L"[OK] Найден NwSapSetup.exe (деинсталлятор)" : L"[НЕТ] NwSapSetup.exe не найден");

    out(L"Компоненты SAP Crypto:");
    int bad = checkCrypto(true);
    out(bad == 0 ? L"[OK] Все компоненты Crypto на месте." : L"[ВНИМАНИЕ] Проблемных компонентов: " + std::to_wstring(bad));

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
    out(L"\n=== Установка SAP GUI 7.70 на " + g_pc + L" ===");
    if (sapInstalled() && !yn(L"SAP GUI уже установлен. Продолжить (обновить/переустановить)?", false)) return;
    if (!exists(SAP770 + L"\\Setup\\NwSapSetup.exe"))
        out(L"[ВНИМАНИЕ] Дистрибутив не виден с этого ПК: " + SAP770 + L" (продолжаю, на удалённом ПК он может быть доступен)");

    struct Step { const wchar_t* title; wstring cmd; };
    std::vector<Step> steps = {
        {L"[1/5] SAP GUI 7.70", SAP770 + L"\\Setup\\NwSapSetup.exe /Silent /Package=SapGui770 /noDLG"},
        {L"[2/5] PDF Print GUI", SAP770 + L"\\Setup\\NwSapSetup.exe /Silent /Product=PdfPrintGui /noDLG"},
        {L"[3/5] Business Explorer", SAP770 + L"\\Setup\\NwSapSetup.exe /Silent /Product=SapBI /noDLG"},
        {L"[4/5] SAP Secure Login Client", SLC + L"\\Setup\\NwSapSetup.exe /Silent /Product=SLC /noDLG"},
    };
    for (auto& s : steps) {
        out(s.title);
        int rc = runPse(s.cmd);
        if (rc != 0) out(L"  [ВНИМАНИЕ] код возврата " + std::to_wstring(rc) + L" (3010 = нужна перезагрузка)");
    }
    out(L"[5/5] SAP Crypto");
    copyCrypto();

    out(L"Применение set_xml_path.reg...");
    runPse(L"regedit /S " + SAP760 + L"\\#\\set_xml_path.reg");

    if (exists(SAP770 + L"\\CheckFileServices.exe")) {
        out(L"Запуск CheckFileServices.exe (без ожидания)...");
        runPse(SAP770 + L"\\CheckFileServices.exe", false);
    }

    if (yn(L"Применить настройки SAP Logon (reg) для вошедшего пользователя?", true)) applyRegToUser();
    showStatus();
}

static void doUninstall() {
    out(L"\n=== Удаление SAP GUI на " + g_pc + L" ===");
    if (!yn(L"Удалить SAP GUI и папку SAP на " + g_pc + L"?", false)) return;
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

// ---------- main ----------
static void chooseComputer() {
    disconnectPc();
    g_pc.clear();
    while (g_pc.empty()) {
        wstring n = ask(L"\nВведите имя компьютера: ");
        while (!n.empty() && n[0] == L'\\') n.erase(0, 1);
        if (n.empty()) continue;
        g_pc = n;
    }
    if (g_user.empty()) {
        wstring u = ask(L"Учётная запись для удалённого запуска (DOMAIN\\user, Enter = SYSTEM/текущая): ");
        if (!u.empty()) { g_user = u; g_pass = askSecret(L"Пароль: "); }
    }
    if (!connectPc()) g_pc.clear();
}

int wmain(int argc, wchar_t** argv) {
    _setmode(_fileno(stdout), _O_U16TEXT);
    _setmode(_fileno(stdin), _O_U16TEXT);
    _setmode(_fileno(stderr), _O_U16TEXT);

    wchar_t me[MAX_PATH];
    GetModuleFileNameW(nullptr, me, MAX_PATH);
    g_exeDir = me;
    g_exeDir = g_exeDir.substr(0, g_exeDir.find_last_of(L'\\') + 1);

    out(L"==================================================");
    out(L"  SAP Manager: SAP GUI 7.70 + SAP Crypto (pse.exe -r " + wstring(PSE_SERVICE) + L")");
    out(L"==================================================");

    if (!findPse()) {
        out(L"[ОШИБКА] pse.exe не найден (положите рядом с программой или в PATH).");
        ask(L"Нажмите Enter...");
        return 1;
    }

    if (argc > 1) { g_pc = argv[1]; if (!connectPc()) g_pc.clear(); }

    for (;;) {
        if (g_pc.empty()) chooseComputer();
        if (g_pc.empty()) continue;
        out(L"\n--- " + g_pc + L" ---");
        out(L"1) Статус: SAP GUI, Crypto, служба реестра, пользователь");
        out(L"2) Установить SAP GUI 7.70 + Crypto + настройки");
        out(L"3) Проверить/скопировать SAP Crypto");
        out(L"4) Применить reg для вошедшего пользователя");
        out(L"5) Удалить SAP GUI");
        out(L"6) Другой компьютер");
        out(L"0) Выход");
        wstring c = ask(L"Выбор: ");
        if (c == L"1") showStatus();
        else if (c == L"2") doInstall();
        else if (c == L"3") {
            out(L"\nКомпоненты SAP Crypto:");
            int bad = checkCrypto(true);
            if (bad && yn(L"Скопировать/обновить компоненты?", true)) { copyCrypto(); checkCrypto(true); }
        }
        else if (c == L"4") applyRegToUser();
        else if (c == L"5") doUninstall();
        else if (c == L"6") g_pc.clear();
        else if (c == L"0") break;
    }
    disconnectPc();
    return 0;
}
