#include <WS2tcpip.h>
#include <winternl.h>
#include <stdio.h>
#include <windows.h>

#include "../CommonLib/CommonLib.h"

#define PORT "50264"
#define DEFAULT_BUFLEN 512 


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

