#include "CommonLib.h"
#include <winternl.h>

pfnNtQuerySystemInformation gNtQueryInformationProcess;

HMODULE LoadNtQueryInformationProcess()
{
	HMODULE hNtdll = LoadLibraryA("ntdll.dll");
	if (hNtdll == nullptr)
		return nullptr;
	gNtQueryInformationProcess = (pfnNtQuerySystemInformation*)GetProcAddress(hNtdll, "NtQueryInformationProcess");
	if (nullptr == gNtQueryInformationProcess)
		return nullptr;
	return hNtdll;
}

BOOL Common::EnableTokenPrivilage(HANDLE hProcess, LPCTSTR pszPrivilage)
{
	HANDLE hToken;
	TOKEN_PRIVILAGE tokenPrivs;
	LUID luidDebug;
	BOOL result;

	if (::OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		if (::LookupPrivilegeValue(L"", pszPrivilage, &luidDebug))
		{
			tokenPrivs.PrivilegeCount = 1;
			tokenPrivs.Privileges[0].Luid = luidDebug;
			tokenPrivs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

			result = AdjustTokenPrivileges(hToken, FALSE, &tokenPrivs, sizeof(tokenPrivs), nullptr, nullptr);
			return result;
		}
	}
	return FALSE;
}

LPVOID Common::GetProcessBasicInformation(HANDLE hProcess)
{
	smPPROCESS_BASIC_INFORMATION pbi = nullptr;
	HANDLE hHeap = nullptr;
	DWORD dwSize = 0;
	DWORD dwSizeNeeded = 0;

	if (!(LoadNtQueryInformationProcess() && EnableTokenPrivilage(hProcess, SE_DEBUG_NAME)))
		return nullptr;

	// Allocate memory for PBI structure
	hHeap = ::GetProcessHeap();
	dwSize = sizeof(smPROCESS_BASIC_INFORMATION);
	pbi = (smPPROCESS_BASIC_INFORMATION)::HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwSize);
	if (nullptr == pbi)
		return nullptr;

	NTSTATUS dwStatus = gNtQueryInformationProcess(hProcess,
		ProcessBasicIformation,
		pbi,
		dwSize,
		&dwSizeNeeded);

	// In a case of a small buffer, try again with the correct size.
	if (dwStatus >= 0 && dwSize < dwSizeNeeded)
	{
		if (pbi)
			::HeapFree(hHeap, 0, pbi);
		pbi = (smPPROCESS_BASIC_INFORMATION)::HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwSizeNeeded);
		if (nullptr == pbi)
			return nullptr;

		dwStatus = gNtQueryInformationProcess(hProcess,
			ProcessBasicIformation,
			pbi,
			dwSizeNeeded,
			&dwSizeNeeded);

	}

	if (dwStatus >= 0)
		return pbi;

	return nullptr;
}

LPVOID Common::GetPebAddress(HANDLE hProcess)
{
	smPPROCESS_BASIC_INFORMATION pbi = (smPPROCESS_BASIC_INFORMATION)GetProcessBasicInformation(hProcess);
	return pbi->PebBaseAddress;
}

LPVOID Common::GetAllRunningProcesses(std::vector<std::pair<DWORD, WCHAR[260]>>& procList)
{
	PROCESSENTRY32 procEntry;
	HANDLE hSnapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	procEntry.dwSize = sizeof(PROCESSENTRY32);

	::Process32First(hSnapshot, &procEntry);
	do {
		std::wstring tempName(procEntry.szExeFile);
		std::pair<DWORD, WCHAR[260]> proc;
		proc.first = procEntry.th32ProcessID;
		wcscpy_s(proc.second, 260, procEntry.szExeFile);

		procList.push_back(proc);

	} while (::Process32Next(hSnapshot, &procEntry));

	return nullptr;
}

DWORD Common::GetPidByProcessName(WCHAR* procName)
{
	std::vector<std::pair<DWORD, WCHAR[260]>> procList;
	Common::GetAllRunningProcesses(procList);

	for (auto& proc : procList)
	{
		if (wcscmp(procName, proc.second) == 0)
			return proc.first;
	}
}

LPVOID Common::ExtractResource(WCHAR* resourceName, DWORD* resourceSize)
{
	HRSRC hResource = ::FindResource(NULL, resourceName, RT_RCDATA);
	if (nullptr == hResource)
		return nullptr;
	HGLOBAL hLoaded = ::LoadResource(NULL, hResource);
	if (nullptr == hLoaded)
		return nullptr;
	LPVOID lpLock = ::LockResource(hLoaded);
	*resourceSize = ::SizeOfResource(0, hResource);

	LPBYTE resource = new BYTE[*resourceSize];
	::memcpy(resource, hLoaded, *resourceSize);
	::FreeResource(hLoaded);
	return resource;
}
