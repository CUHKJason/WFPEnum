#include <stddef.h>
#include <stdio.h>
#include <wchar.h>
#include <windows.h>
#include <initguid.h>
#include <fwpmu.h>
#include <tlhelp32.h>

#define NtCurrentProcess      ( ( HANDLE ) (LONG_PTR ) -1 )
#define NtCurrentThread       ( ( HANDLE )( LONG_PTR ) -2 )

// d78e1e87-8644-4ea5-9437-d809ecefc971
DEFINE_GUID(
   FWPM_CONDITION_ALE_APP_ID,
   0xd78e1e87,
   0x8644,
   0x4ea5,
   0x94, 0x37, 0xd8, 0x09, 0xec, 0xef, 0xc9, 0x71
);

// b235ae9a-1d64-49b8-a44c-5ff3d9095045
DEFINE_GUID(
   FWPM_CONDITION_IP_REMOTE_ADDRESS,
   0xb235ae9a,
   0x1d64,
   0x49b8,
   0xa4, 0x4c, 0x5f, 0xf3, 0xd9, 0x09, 0x50, 0x45
);

// c38d57d1-05a7-4c33-904f-7fbceee60e82
DEFINE_GUID(
   FWPM_LAYER_ALE_AUTH_CONNECT_V4,
   0xc38d57d1,
   0x05a7,
   0x4c33,
   0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82
);

// 4a72393b-319f-44bc-84c3-ba54dcb3b6b4
DEFINE_GUID(
   FWPM_LAYER_ALE_AUTH_CONNECT_V6,
   0x4a72393b,
   0x319f,
   0x44bc,
   0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4
);

typedef enum ErrorCode {
    CUSTOM_SUCCESS = 0,
    CUSTOM_FILE_NOT_FOUND = 0x1,
    CUSTOM_MEMORY_ALLOCATION_ERROR = 0x2,
    CUSTOM_NULL_INPUT = 0x3,
    CUSTOM_DRIVE_NAME_NOT_FOUND = 0x4,
    CUSTOM_FAILED_TO_GET_DOS_DEVICE_NAME = 0x5,
} ErrorCode;

#define FWPM_PROVIDER_FLAG_PERSISTENT (0x00000001)
#define FWPM_SUBLAYER_FLAG_PERSISTENT (0x00000001)


// Fwpuclnt functions
typedef DWORD (WINAPI *__FwpmProviderAdd0)(
    HANDLE               engineHandle,
    const FWPM_PROVIDER0 *provider,
    PSECURITY_DESCRIPTOR sd
);
typedef DWORD (WINAPI *__FwpmFilterAdd0)(
    HANDLE               engineHandle,
    const FWPM_FILTER0   *filter,
    PSECURITY_DESCRIPTOR sd,
    UINT64               *id
);
typedef DWORD (WINAPI *__FwpmEngineOpen0)(
    const wchar_t             *serverName,
    UINT32                    authnService,
    SEC_WINNT_AUTH_IDENTITY_W *authIdentity,
    const FWPM_SESSION0       *session,
    HANDLE                    *engineHandle
);

typedef DWORD (WINAPI *__FwpmFilterGetById0)(
    HANDLE               engineHandle,
    UINT64               id,
    const FWPM_FILTER0   **filter
);

typedef DWORD (WINAPI *__FwpmEngineClose0)(HANDLE engineHandle);
typedef DWORD (WINAPI *__FwpmProviderCreateEnumHandle0)(
    HANDLE                             engineHandle,
    const FWPM_PROVIDER_ENUM_TEMPLATE0 *enumTemplate,
    HANDLE                             *enumHandle
);
typedef DWORD (WINAPI *__FwpmProviderDestroyEnumHandle0)(HANDLE engineHandle, HANDLE enumHandle);
typedef DWORD (WINAPI *__FwpmFilterCreateEnumHandle0)(
    HANDLE                           engineHandle,
    const FWPM_FILTER_ENUM_TEMPLATE0 *enumTemplate,
    HANDLE                           *enumHandle
);
typedef DWORD (WINAPI *__FwpmSubLayerCreateEnumHandle0)(
    HANDLE                           engineHandle,
    const const FWPM_SUBLAYER_ENUM_TEMPLATE0 *enumTemplate,
    HANDLE                           *enumHandle
);
typedef DWORD (WINAPI *__FwpmSubLayerDestroyEnumHandle0)(HANDLE engineHandle, HANDLE enumHandle);
typedef DWORD (WINAPI *__FwpmFilterDestroyEnumHandle0)(HANDLE engineHandle, HANDLE enumHandle);
typedef DWORD (WINAPI *__FwpmProviderEnum0)(
    HANDLE         engineHandle,
    HANDLE         enumHandle,
    UINT32         numEntriesRequested,
    FWPM_PROVIDER0 ***entries,
    UINT32         *numEntriesReturned
);
typedef DWORD (WINAPI *__FwpmFilterEnum0)(
    HANDLE       engineHandle,
    HANDLE       enumHandle,
    UINT32       numEntriesRequested,
    FWPM_FILTER0 ***entries,
    UINT32       *numEntriesReturned
);
typedef DWORD (WINAPI *__FwpmSubLayerEnum0)(
    HANDLE       engineHandle,
    HANDLE       enumHandle,
    UINT32       numEntriesRequested,
    FWPM_SUBLAYER0  ***entries,
    UINT32       *numEntriesReturned
);
typedef DWORD (WINAPI *__FwpmProviderDeleteByKey0)(HANDLE engineHandle, const GUID *key);
typedef DWORD (WINAPI *__FwpmFilterDeleteById0)(HANDLE engineHandle, UINT64 id);
typedef void (WINAPI *__FwpmFreeMemory0)(void **p);

__FwpmProviderAdd0 _FwpmProviderAdd0 = NULL;
__FwpmFilterAdd0 _FwpmFilterAdd0 = NULL;
__FwpmEngineOpen0 _FwpmEngineOpen0 = NULL;
__FwpmFilterGetById0 _FwpmFilterGetById0 = NULL;
__FwpmEngineClose0 _FwpmEngineClose0 = NULL;
__FwpmProviderCreateEnumHandle0 _FwpmProviderCreateEnumHandle0 = NULL;
__FwpmProviderDestroyEnumHandle0 _FwpmProviderDestroyEnumHandle0 = NULL;
__FwpmFilterCreateEnumHandle0 _FwpmFilterCreateEnumHandle0 = NULL;
__FwpmFilterDestroyEnumHandle0 _FwpmFilterDestroyEnumHandle0 = NULL;
__FwpmProviderEnum0 _FwpmProviderEnum0 = NULL;
__FwpmFilterEnum0 _FwpmFilterEnum0 = NULL;
__FwpmProviderDeleteByKey0 _FwpmProviderDeleteByKey0 = NULL;
__FwpmFilterDeleteById0 _FwpmFilterDeleteById0 = NULL;
__FwpmFreeMemory0 _FwpmFreeMemory0 = NULL;
__FwpmSubLayerCreateEnumHandle0 _FwpmSubLayerCreateEnumHandle0 = NULL;
__FwpmSubLayerDestroyEnumHandle0 _FwpmSubLayerDestroyEnumHandle0 = NULL;
__FwpmSubLayerEnum0 _FwpmSubLayerEnum0 = NULL;

BOOL InitFWPM(){
    HMODULE fwpuclnt = KERNEL32$LoadLibraryA("Fwpuclnt.dll");
    if (!fwpuclnt){
        err("LoadLibraryA failed: 0x%lx.\n", KERNEL32$GetLastError());
        return FALSE;
    }
    _FwpmProviderAdd0 = (__FwpmProviderAdd0)KERNEL32$GetProcAddress(fwpuclnt, "FwpmProviderAdd0");
    _FwpmFilterAdd0 = (__FwpmFilterAdd0)KERNEL32$GetProcAddress(fwpuclnt, "FwpmFilterAdd0");
    _FwpmEngineOpen0 = (__FwpmEngineOpen0)KERNEL32$GetProcAddress(fwpuclnt, "FwpmEngineOpen0");
    _FwpmFilterGetById0 = (__FwpmFilterGetById0)KERNEL32$GetProcAddress(fwpuclnt, "FwpmFilterGetById0");
    _FwpmEngineClose0 = (__FwpmEngineClose0)KERNEL32$GetProcAddress(fwpuclnt, "FwpmEngineClose0");
    _FwpmProviderCreateEnumHandle0 = (__FwpmProviderCreateEnumHandle0)KERNEL32$GetProcAddress(fwpuclnt, "FwpmProviderCreateEnumHandle0");
    _FwpmProviderDestroyEnumHandle0 = (__FwpmProviderDestroyEnumHandle0)KERNEL32$GetProcAddress(fwpuclnt, "FwpmProviderDestroyEnumHandle0");
    _FwpmFilterCreateEnumHandle0 = (__FwpmFilterCreateEnumHandle0)KERNEL32$GetProcAddress(fwpuclnt, "FwpmFilterCreateEnumHandle0");
    _FwpmFilterDestroyEnumHandle0 = (__FwpmFilterDestroyEnumHandle0)KERNEL32$GetProcAddress(fwpuclnt, "FwpmFilterDestroyEnumHandle0");
    _FwpmProviderEnum0 = (__FwpmProviderEnum0)KERNEL32$GetProcAddress(fwpuclnt, "FwpmProviderEnum0");
    _FwpmFilterEnum0 = (__FwpmFilterEnum0)KERNEL32$GetProcAddress(fwpuclnt, "FwpmFilterEnum0");
    _FwpmProviderDeleteByKey0 = (__FwpmProviderDeleteByKey0)KERNEL32$GetProcAddress(fwpuclnt, "FwpmProviderDeleteByKey0");
    _FwpmFilterDeleteById0 = (__FwpmFilterDeleteById0)KERNEL32$GetProcAddress(fwpuclnt, "FwpmFilterDeleteById0");
    _FwpmFreeMemory0 = (__FwpmFreeMemory0)KERNEL32$GetProcAddress(fwpuclnt, "FwpmFreeMemory0");
    _FwpmSubLayerCreateEnumHandle0 = (__FwpmSubLayerCreateEnumHandle0)KERNEL32$GetProcAddress(fwpuclnt, "FwpmSubLayerCreateEnumHandle0");
    _FwpmSubLayerDestroyEnumHandle0 = (__FwpmSubLayerDestroyEnumHandle0)KERNEL32$GetProcAddress(fwpuclnt, "FwpmSubLayerDestroyEnumHandle0");
    _FwpmSubLayerEnum0 = (__FwpmSubLayerEnum0)KERNEL32$GetProcAddress(fwpuclnt, "FwpmSubLayerEnum0");

    return TRUE;
}

INT StringCompareA( _In_ LPCSTR String1, _In_ LPCSTR String2 )
{
    for ( ; *String1 == *String2; String1++, String2++ )
    {
        if ( *String1 == '\0' )
        {
            return 0;
        };
    };
    return ( ( *( LPCSTR )String1 < *( LPCSTR )String2 ) ? -1 : +1 );
};

INT StringCompareW(_In_ LPCWSTR String1, _In_ LPCWSTR String2)
{
    for (; *String1 == *String2; String1++, String2++)
    {
        if (*String1 == '\0')
            return 0;
    }

    return ((*(LPCWSTR)String1 < *(LPCWSTR)String2) ? -1 : +1);
}

SIZE_T StringLengthW(_In_ LPCWSTR String)
{
    LPCWSTR String2;

    for (String2 = String; *String2; ++String2);

    return (String2 - String);
}

PVOID CopyMemoryEx(_Inout_ PVOID Destination, _In_ CONST PVOID Source, _In_ SIZE_T Length)
{
    PBYTE D = (PBYTE)Destination;
    PBYTE S = (PBYTE)Source;

    while (Length--)
        *D++ = *S++;

    return Destination;
}

PWCHAR StringCopyW(_Inout_ PWCHAR String1, _In_ LPCWSTR String2, INT count)
{
    PWCHAR p = String1;
    INT i = 0;
    while ( i <= count && (*p++ = *String2++) != 0){
        i++;
    }

    return String1;
}

PWCHAR ToLower(_In_ PWCHAR Ptr)
{
    PWCHAR sv = Ptr;
    while (*sv != '\0')
    {
        if (*sv >= 'A' && *sv <= 'Z')
            *sv = *sv + ('a' - 'A');

        sv++;
    }
    return Ptr;
}

PWCHAR StringLocateCharW(_Inout_ PCWSTR String, _In_ INT Character)
{
    do
    {
        if (*String == Character)
            return (PWCHAR)String;

    } while (*String++);

    return NULL;
}

UINT64 StringToUINT64(const char *str, char **endptr, int base) {
    unsigned long long result = 0;
    int digit;

    // Skip leading white-space characters
    while (*str == ' ' || (*str >= '\t' && *str <= '\r')) {
        str++;
    }

    // Determine the base if not specified
    if (base == 0) {
        if (*str == '0') {
            base = (*(str + 1) == 'x' || *(str + 1) == 'X') ? 16 : 8;
        } else {
            base = 10;
        }
    }

    // Handle hexadecimal prefix if present
    if (base == 16 && *str == '0' && (*(str + 1) == 'x' || *(str + 1) == 'X')) {
        str += 2;
    }

    // Process digits
    while ((digit = *str - '0') >= 0) {
        if (digit > base) {
            break;  // Invalid digit for the base
        }
        result = result * base + digit;
        str++;
    }

    // Set endptr if provided
    if (endptr != NULL) {
        *endptr = (char*)str;
    }

    return result;
}

/*
s1 and s2 are the string sizes NOT counting terminating NULL, dstSz is the TOTAL destination string size, including termination
*/
BOOL StringConcatW(PWCHAR dest, size_t dstSz, PCWSTR str1, size_t s1, PCWSTR str2, size_t s2){
    if (s1 > StringLengthW(str1) || s2 > StringLengthW(str2) || dstSz < s1 + s2 + 1){
        //printf("bad input string size\n");
        return FALSE;
    }
    for (int i = 0; i < s1; i++){
        dest[i] = str1[i];
    }
    for (int i = 0; i < s2; i++){
        dest[s1+i] = str2[i];
    }
    dest[dstSz-1] = '\0';
    return TRUE;
}

BOOL CheckProcessIntegrityLevel() {
    HANDLE hToken = NULL;
    DWORD dwLength = 0;
    PTOKEN_MANDATORY_LABEL pTIL = NULL;
    DWORD dwIntegrityLevel = 0;
    BOOL isHighIntegrity = FALSE;

    if (!ADVAPI32$OpenThreadToken(NtCurrentThread, TOKEN_QUERY, TRUE, &hToken)) {
        if (KERNEL32$GetLastError() != ERROR_NO_TOKEN) {
            err("OpenThreadToken failed with error code: 0x%lx.\n", KERNEL32$GetLastError());
            return FALSE;
        }

        if (!ADVAPI32$OpenProcessToken(NtCurrentProcess, TOKEN_QUERY, &hToken)) {
            err("OpenProcessToken failed with error code: 0x%lx.\n", KERNEL32$GetLastError());
            return FALSE;
        }
    }

    // Get the size of the integrity level information
    if (!ADVAPI32$GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwLength) && 
        KERNEL32$GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        err("GetTokenInformation failed with error code: 0x%lx.\n", KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hToken);
        return FALSE;
    }

    pTIL = (PTOKEN_MANDATORY_LABEL)KERNEL32$LocalAlloc(LPTR, dwLength);
    if (pTIL == NULL) {
        err("LocalAlloc failed with error code: 0x%lx.\n", KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hToken);
        return FALSE;
    }

    if (!ADVAPI32$GetTokenInformation(hToken, TokenIntegrityLevel, pTIL, dwLength, &dwLength)) {
        err("GetTokenInformation failed with error code: 0x%lx.\n", KERNEL32$GetLastError());
        KERNEL32$LocalFree(pTIL);
        KERNEL32$CloseHandle(hToken);
        return FALSE;
    }

    dwIntegrityLevel = *ADVAPI32$GetSidSubAuthority(pTIL->Label.Sid, (DWORD)(UCHAR)(*ADVAPI32$GetSidSubAuthorityCount(pTIL->Label.Sid) - 1));

    if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID) {
        isHighIntegrity = TRUE;
    } else {
        err("This program requires to run in high integrity level.\n");
    }

    KERNEL32$LocalFree(pTIL);
    KERNEL32$CloseHandle(hToken);
    return isHighIntegrity;
}

// Enable SeDebugPrivilege to obtain full path of running processes
BOOL EnableSeDebugPrivilege() {
	HANDLE hToken = NULL;
	TOKEN_PRIVILEGES tokenPrivileges = {0};
	
    if (!ADVAPI32$OpenThreadToken(NtCurrentThread, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, TRUE, &hToken)) {
        if (KERNEL32$GetLastError() != ERROR_NO_TOKEN) {
            err("OpenThreadToken failed with error code: 0x%lx.\n", KERNEL32$GetLastError());
            return FALSE;
        }

        if (!ADVAPI32$OpenProcessToken(NtCurrentProcess, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken)) {
            err("OpenProcessToken failed with error code: 0x%lx.\n", KERNEL32$GetLastError());
            return FALSE;
        }
    }

	if (!ADVAPI32$LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &tokenPrivileges.Privileges[0].Luid)){
        err("LookupPrivilegeValueA failed with error code: 0x%lx.\n", KERNEL32$GetLastError());
		KERNEL32$CloseHandle(hToken);
		return FALSE;
	}

	tokenPrivileges.PrivilegeCount = 1;
	tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!ADVAPI32$AdjustTokenPrivileges(hToken, FALSE, &tokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        err("AdjustTokenPrivileges failed with error code: 0x%lx.\n", KERNEL32$GetLastError());
		KERNEL32$CloseHandle(hToken);
		return FALSE;
	}

    if (KERNEL32$GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        err("Failed to get SeDebugPrivilege. You might not be able to get the process handle of the EDR process.\n");
		KERNEL32$CloseHandle(hToken);
		return FALSE;
    }

	KERNEL32$CloseHandle(hToken);
	return TRUE;
}

void CharArrayToWCharArray(const char charArray[], WCHAR wCharArray[], size_t wCharArraySize) {
    int result = KERNEL32$MultiByteToWideChar(CP_UTF8, 0, charArray, -1, wCharArray, wCharArraySize);

    if (result == 0) {
        err("MultiByteToWideChar failed with error code: 0x%lx.\n", KERNEL32$GetLastError());
        wCharArray[0] = L'\0';
    }
}

BOOL GetDriveName(PCWSTR filePath, wchar_t* driveName, size_t driveNameSize) {
    if (!filePath) {
        return FALSE;
    }
    const wchar_t *colon = StringLocateCharW(filePath, L':');
    if (colon && (colon - filePath + 1) < driveNameSize) {
        StringCopyW(driveName, filePath, colon - filePath + 1);
        driveName[colon - filePath + 1] = L'\0';
        return TRUE;
    } else {
        return FALSE;
    }
}

#define MAX_DRIVE_PATH 100
ErrorCode ConvertToNtPath(PCWSTR filePath, wchar_t* ntPathBuffer, size_t bufferSize) {
    WCHAR driveName[10];
    WCHAR ntDrivePath[MAX_DRIVE_PATH];
    if (!filePath || !ntPathBuffer) {
        return CUSTOM_NULL_INPUT;
    }

    if (!GetDriveName(filePath, driveName, sizeof(driveName) / sizeof(WCHAR))) {
        return CUSTOM_DRIVE_NAME_NOT_FOUND;
    }

    if (KERNEL32$QueryDosDeviceW(driveName, ntDrivePath, sizeof(ntDrivePath) / sizeof(WCHAR)) == 0) {
        return CUSTOM_FAILED_TO_GET_DOS_DEVICE_NAME;
    }

    //MSVCRT$swprintf(ntPathBuffer, bufferSize, L"%S%S", ntDrivePath, filePath + StringLengthW(driveName));
    size_t pathLen = StringLengthW(filePath) - StringLengthW(driveName);
    size_t ntDrivePathLen = StringLengthW(ntDrivePath);
    if (!StringConcatW(ntPathBuffer, bufferSize, ntDrivePath, ntDrivePathLen, filePath + StringLengthW(driveName), pathLen)){
        return CUSTOM_MEMORY_ALLOCATION_ERROR;
    }

    ntPathBuffer = ToLower(ntPathBuffer);
    //for (size_t i = 0; ntPathBuffer[i] != L'\0'; ++i) {
    //    ntPathBuffer[i] = towlower(ntPathBuffer[i]);
    //}
    ntPathBuffer[ntDrivePathLen + pathLen] = L'\0';
    return CUSTOM_SUCCESS;
}

BOOL FileExists(PCWSTR filePath) {
    if (!filePath) {
        return FALSE;
    }

    DWORD fileAttrib = KERNEL32$GetFileAttributesW(filePath);
    if (fileAttrib == INVALID_FILE_ATTRIBUTES) {
        return FALSE;
    }

    return TRUE;
}

ErrorCode CustomFwpmGetAppIdFromFileName0(PCWSTR filePath, FWP_BYTE_BLOB** appId) {
    if (!FileExists(filePath)) {
        return CUSTOM_FILE_NOT_FOUND;
    }

    WCHAR ntPath[MAX_PATH+MAX_DRIVE_PATH+1];
    ErrorCode errorCode = ConvertToNtPath(filePath, ntPath, MAX_PATH);

    if (errorCode != CUSTOM_SUCCESS) {
        return errorCode;
    }
    *appId = (FWP_BYTE_BLOB*)intAlloc(sizeof(FWP_BYTE_BLOB));
    if (!*appId) {
        return CUSTOM_MEMORY_ALLOCATION_ERROR;
    }

    (*appId)->size = StringLengthW(ntPath) * sizeof(WCHAR) + sizeof(WCHAR);
    
    (*appId)->data = (UINT8*)intAlloc((*appId)->size);
    if (!(*appId)->data) {
        intFree(*appId);
        return CUSTOM_MEMORY_ALLOCATION_ERROR;
    }
    CopyMemoryEx((*appId)->data, ntPath, (*appId)->size);
    return CUSTOM_SUCCESS;
}

void FreeAppId(FWP_BYTE_BLOB* appId) {
    if (appId) {
        if (appId->data) {
            intFree(appId->data);
        }
        intFree(appId);
    }
}

// Get provider GUID by description
BOOL GetProviderGUIDByDescription(PCWSTR providerDescription, GUID* outProviderGUID) {
    DWORD result = 0;
    HANDLE hEngine = NULL;
    HANDLE enumHandle = NULL;
    FWPM_PROVIDER0** providers = NULL;
    UINT32 numProviders = 0;

    result = _FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, NULL, &hEngine);
    if (result != ERROR_SUCCESS) {
        err("FwpmEngineOpen0 failed with error code: 0x%lx.\n", result);
        return FALSE;
    }

    result = _FwpmProviderCreateEnumHandle0(hEngine, NULL, &enumHandle);
    if (result != ERROR_SUCCESS) {
        err("FwpmProviderCreateEnumHandle0 failed with error code: 0x%lx.\n", result);
        _FwpmEngineClose0(hEngine);
        return FALSE;
    }

    result = _FwpmProviderEnum0(hEngine, enumHandle, 100, &providers, &numProviders);
    if (result != ERROR_SUCCESS) {
        err("FwpmProviderEnum0 failed with error code: 0x%lx.\n", result);
        _FwpmEngineClose0(hEngine);
        return FALSE;
    }

    for (UINT32 i = 0; i < numProviders; i++) {
        if (providers[i]->displayData.description != NULL) {
            if (StringCompareW(providers[i]->displayData.description, providerDescription) == 0) {
                *outProviderGUID = providers[i]->providerKey;
                return TRUE;
            }
        }   
    }

    if (providers) {
        _FwpmFreeMemory0((void**)&providers);
    }

    _FwpmProviderDestroyEnumHandle0(hEngine, enumHandle);
    _FwpmEngineClose0(hEngine);
    return FALSE;
}