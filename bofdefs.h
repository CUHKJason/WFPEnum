
#pragma once
#include <stdio.h>
#include <windows.h>
#include <initguid.h>
#include <fwpmu.h>
#include <tlhelp32.h>
#include <rpcdce.h>

#define _In_NLS_string_(size)     _When_((size) < 0,  _In_z_)           \
                                  _When_((size) >= 0, _In_reads_(size))

#ifdef BOF

WINBASEAPI void *__cdecl MSVCRT$malloc(size_t size);
WINBASEAPI int __cdecl MSVCRT$sscanf(const char *buffer,const char *format, ... );
DECLSPEC_IMPORT int     WINAPI OLE32$StringFromGUID2 (REFGUID rguid, LPOLESTR lpsz, int cchMax);
WINBASEAPI size_t __cdecl MSVCRT$strlen(const char *_Str);

WINBASEAPI void __cdecl MSVCRT$memset(void *dest, int c, size_t count);
DECLSPEC_IMPORT RPC_STATUS WINAPI RPCRT4$UuidCreate(UUID *Uuid);

WINBASEAPI void __cdecl MSVCRT$free(void *);
WINBASEAPI INT WINAPI WS2_32$inet_pton(INT Family, LPCSTR pStringBuf, PVOID pAddr);
DECLSPEC_IMPORT char * __stdcall WS2_32$inet_ntoa(struct in_addr in);

DECLSPEC_IMPORT FILE* __cdecl MSVCRT$fopen(const char* _Filename, const char* _Mode);
DECLSPEC_IMPORT int __cdecl MSVCRT$fclose(FILE* _File);
DECLSPEC_IMPORT int __cdecl MSVCRT$fprintf(FILE* _File, const char *format, ...);
WINBASEAPI int       __cdecl MSVCRT$sprintf_s(char *_DstBuf, size_t _DstSize, const char *_Format, ...);
WINBASEAPI char *       __cdecl MSVCRT$strcat_s(char *strDestination,  size_t numberOfElements,  const char *strSource);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$WriteFile(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);

DECLSPEC_IMPORT HLOCAL WINAPI KERNEL32$LocalAlloc (UINT, SIZE_T);
DECLSPEC_IMPORT HLOCAL WINAPI KERNEL32$LocalFree (HLOCAL);
WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap();
WINBASEAPI void * WINAPI KERNEL32$HeapAlloc (HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
WINBASEAPI BOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, PVOID);

WINBASEAPI HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD dwFlags,DWORD th32ProcessID);
WINBASEAPI WINBOOL WINAPI KERNEL32$Process32First(HANDLE hSnapshot,LPPROCESSENTRY32 lppe);
WINBASEAPI WINBOOL WINAPI KERNEL32$Process32Next(HANDLE hSnapshot,LPPROCESSENTRY32 lppe);
WINBASEAPI HANDLE WINAPI KERNEL32$OpenProcess(DWORD dwDesiredAccess, WINBOOL bInheritHandle, DWORD dwProcessId);
WINBASEAPI WINBOOL WINAPI KERNEL32$CloseHandle(HANDLE hObject);
WINBASEAPI DWORD WINAPI KERNEL32$GetFileAttributesW (LPCWSTR lpFileName);
WINBASEAPI DWORD WINAPI KERNEL32$QueryDosDeviceW(LPCWSTR lpDeviceName, LPWSTR lpTargetPath, DWORD ucchMax);
WINBASEAPI DWORD WINAPI KERNEL32$GetLastError (VOID);
WINBASEAPI DWORD WINAPI KERNEL32$QueryFullProcessImageNameW(HANDLE hProcess, DWORD  dwFlags, LPWSTR lpExeName,PDWORD lpdwSize);
WINBASEAPI int WINAPI KERNEL32$MultiByteToWideChar(
	UINT                              CodePage,
	DWORD                             dwFlags,
	_In_NLS_string_(cbMultiByte)LPCCH lpMultiByteStr,
	int                               cbMultiByte,
	LPWSTR                            lpWideCharStr,
	int                               cchWideChar
);
WINBASEAPI HMODULE WINAPI KERNEL32$LoadLibraryA(LPCSTR lpLibFileName);
WINBASEAPI FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE hModule, LPCSTR lpProcName);

//advapi32 functions
WINADVAPI WINBOOL WINAPI ADVAPI32$GetTokenInformation(
	HANDLE TokenHandle, 
	TOKEN_INFORMATION_CLASS TokenInformationClass, 
	LPVOID TokenInformation, 
	DWORD TokenInformationLength, 
	PDWORD ReturnLength);
WINADVAPI WINBOOL WINAPI ADVAPI32$OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
WINADVAPI WINBOOL WINAPI ADVAPI32$OpenThreadToken(
	HANDLE  ThreadHandle,
	DWORD   DesiredAccess,
	BOOL    OpenAsSelf,
	PHANDLE TokenHandle
);
WINADVAPI PDWORD WINAPI ADVAPI32$GetSidSubAuthority(PSID  pSid, DWORD nSubAuthority);
WINADVAPI PUCHAR WINAPI ADVAPI32$GetSidSubAuthorityCount(PSID pSid);
WINADVAPI PDWORD WINAPI ADVAPI32$LookupPrivilegeValueA(
	LPCSTR lpSystemName,
	LPCSTR lpName,
	PLUID  lpLuid
);
WINADVAPI PDWORD WINAPI ADVAPI32$AdjustTokenPrivileges(
	HANDLE            TokenHandle,
	BOOL              DisableAllPrivileges,
	PTOKEN_PRIVILEGES NewState,
	DWORD             BufferLength,
	PTOKEN_PRIVILEGES PreviousState,
	PDWORD            ReturnLength
);

//WINBASEAPI int __cdecl MSVCRT$_snwprintf(wchar_t * __restrict__ _Dest,size_t _Count,const wchar_t * __restrict__ _Format,...);
//WINBASEAPI int __cdecl MSVCRT$swprintf(wchar_t *__stream, const wchar_t *__format, ...);


#define printf(fmt, ...) BeaconPrintf(CALLBACK_OUTPUT, fmt, ##__VA_ARGS__ )
#define msg(fmt, ...) BeaconPrintf(CALLBACK_OUTPUT, fmt, ##__VA_ARGS__ )
#define err(fmt, ...) BeaconPrintf(CALLBACK_ERROR, fmt, ##__VA_ARGS__ )

#define intAlloc(size) 				KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, size)
#define intFree(addr) 				KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, addr)
#else

#include <stdio.h>

#define KERNEL32$LocalAlloc LocalAlloc
#define KERNEL32$LocalFree LocalFree
#define KERNEL32$GetProcessHeap GetProcessHeap
#define KERNEL32$HeapAlloc HeapAlloc
#define KERNEL32$HeapFree HeapFree
#define KERNEL32$CreateToolhelp32Snapshot CreateToolhelp32Snapshot
#define KERNEL32$Process32First Process32First
#define KERNEL32$Process32Next Process32Next
#define KERNEL32$OpenProcess OpenProcess
#define KERNEL32$CloseHandle CloseHandle
#define KERNEL32$GetFileAttributesW GetFileAttributesW
#define KERNEL32$QueryDosDeviceW QueryDosDeviceW
#define KERNEL32$GetLastError GetLastError
#define KERNEL32$QueryFullProcessImageNameW QueryFullProcessImageNameW
#define KERNEL32$MultiByteToWideChar MultiByteToWideChar
#define KERNEL32$LoadLibraryA LoadLibraryA
#define KERNEL32$GetProcAddress GetProcAddress
#define ADVAPI32$GetTokenInformation GetTokenInformation
#define ADVAPI32$OpenProcessToken OpenProcessToken
#define ADVAPI32$OpenThreadToken OpenThreadToken
#define ADVAPI32$GetSidSubAuthority GetSidSubAuthority
#define ADVAPI32$GetSidSubAuthorityCount GetSidSubAuthorityCount
#define ADVAPI32$LookupPrivilegeValueA LookupPrivilegeValueA
#define ADVAPI32$AdjustTokenPrivileges AdjustTokenPrivileges
#define MSVCRT$swprintf swprintf

#define intAlloc(size) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size)
#define intRealloc(ptr, size) HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ptr, size) 
#define intFree(addr) HeapFree(GetProcessHeap(), 0, addr)

#define msg(fmt, ...) printf(fmt, ##__VA_ARGS__ )
#define err(fmt, ...) printf(fmt, ##__VA_ARGS__ )

#endif