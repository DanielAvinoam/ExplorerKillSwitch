#pragma once
#include <windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <vector>
#include <strsafe.h>
#include <psapi.h>
#include <winternl.h>

#define MAX_UNICODE_PATH 32767L

// NtQuerySystemInformation from ntdll.dll
typedef NTSTATUS(NTAPI* pfnNtQuerySystemInformation)(
    IN HANDLE 				ProcessHandle,
    IN PROCESSINFOCLASS 	ProcessInformationClass,
    OUT PVOID   			SystemInformation,
    IN ULONG    			SystemInformationLength,
    OUT PULONG  			ReturnLength OPTIONAL);

// Used in PEB struct
typedef ULONG smPPS_POST_PROCESS_INIT_ROUTINE;

// Used in PEB struct
typedef struct _smPEB_LDR_DATA
{
    ULONG Length;
    UCHAR Initialized;
    PVOID SsHandle;
    struct _LIST_ENTRY InLoadOrderModuleList;
    struct _LIST_ENTRY InMemoryOrderModuleList;
    struct _LIST_ENTRY InInitializationOrderModuleList;
    PVOID EntryInProgress;
} smPEB_LDR_DATA, * smPPEB_LDR_DATA;

//0xe0 bytes (sizeof)
typedef struct _smLDR_DATA_TABLE_ENTRY
{
    struct _LIST_ENTRY InLoadOrderLinks;                                    //0x0
    struct _LIST_ENTRY InMemoryOrderLinks;                                  //0x10
    struct _LIST_ENTRY InInitializationOrderLinks;                          //0x20
    VOID* DllBase;                                                          //0x30
    VOID* EntryPoint;                                                       //0x38
    ULONG SizeOfImage;                                                      //0x40
    struct _UNICODE_STRING FullDllName;                                     //0x48
    struct _UNICODE_STRING BaseDllName;                                     //0x58
    ULONG Flags;                                                            //0x68
    USHORT LoadCount;                                                       //0x6c
    USHORT TlsIndex;                                                        //0x6e
    union
    {
        struct _LIST_ENTRY HashLinks;                                       //0x70
        struct
        {
            VOID* SectionPointer;                                           //0x70
            ULONG CheckSum;                                                 //0x78
        };
    };
    union
    {
        ULONG TimeDateStamp;                                                //0x80
        VOID* LoadedImports;                                                //0x80
    };
    struct _ACTIVATION_CONTEXT* EntryPointActivationContext;                //0x88
    VOID* PatchInformation;                                                 //0x90
    struct _LIST_ENTRY ForwarderLinks;                                      //0x98
    struct _LIST_ENTRY ServiceTagLinks;                                     //0xa8
    struct _LIST_ENTRY StaticLinks;                                         //0xb8
    VOID* ContextInformation;                                               //0xc8
    ULONGLONG OriginalBase;                                                 //0xd0
    union _LARGE_INTEGER LoadTime;                                          //0xd8
} smLDR_DATA_TABLE_ENTRY, * smPLDR_DATA_TABLE_ENTRY;

// Used in PEB struct
typedef struct _smRTL_USER_PROCESS_PARAMETERS
{
    ULONG MaximumLength;                                                    //0x0
    ULONG Length;                                                           //0x4
    ULONG Flags;                                                            //0x8
    ULONG DebugFlags;                                                       //0xc
    VOID* ConsoleHandle;                                                    //0x10
    ULONG ConsoleFlags;                                                     //0x18
    VOID* StandardInput;                                                    //0x20
    VOID* StandardOutput;                                                   //0x28
    VOID* StandardError;                                                    //0x30
    struct _CURDIR CurrentDirectory;                                        //0x38
    struct _UNICODE_STRING DllPath;                                         //0x50
    struct _UNICODE_STRING ImagePathName;                                   //0x60
    struct _UNICODE_STRING CommandLine;                                     //0x70
    VOID* Environment;                                                      //0x80
    ULONG StartingX;                                                        //0x88
    ULONG StartingY;                                                        //0x8c
    ULONG CountX;                                                           //0x90
    ULONG CountY;                                                           //0x94
    ULONG CountCharsX;                                                      //0x98
    ULONG CountCharsY;                                                      //0x9c
    ULONG FillAttribute;                                                    //0xa0
    ULONG WindowFlags;                                                      //0xa4
    ULONG ShowWindowFlags;                                                  //0xa8
    struct _UNICODE_STRING WindowTitle;                                     //0xb0
    struct _UNICODE_STRING DesktopInfo;                                     //0xc0
    struct _UNICODE_STRING ShellInfo;                                       //0xd0
    struct _UNICODE_STRING RuntimeData;                                     //0xe0
    struct _RTL_DRIVE_LETTER_CURDIR CurrentDirectores[32];                  //0xf0
    volatile ULONGLONG EnvironmentSize;                                     //0x3f0
    volatile ULONGLONG EnvironmentVersion;                                  //0x3f8
} smRTL_USER_PROCESS_PARAMETERS, * smPRTL_USER_PROCESS_PARAMETERS;

//0x380 bytes (sizeof)
typedef struct _smPEB
{
    UCHAR InheritedAddressSpace;                                            //0x0
    UCHAR ReadImageFileExecOptions;                                         //0x1
    UCHAR BeingDebugged;                                                    //0x2
    union
    {
        UCHAR BitField;                                                     //0x3
        struct
        {
            UCHAR ImageUsesLargePages : 1;                                    //0x3
            UCHAR IsProtectedProcess : 1;                                     //0x3
            UCHAR IsLegacyProcess : 1;                                        //0x3
            UCHAR IsImageDynamicallyRelocated : 1;                            //0x3
            UCHAR SkipPatchingUser32Forwarders : 1;                           //0x3
            UCHAR SpareBits : 3;                                              //0x3
        };
    };
    VOID* Mutant;                                                           //0x8
    VOID* ImageBaseAddress;                                                 //0x10
    struct _PEB_LDR_DATA* Ldr;                                              //0x18
    struct _RTL_USER_PROCESS_PARAMETERS* ProcessParameters;                 //0x20
    VOID* SubSystemData;                                                    //0x28
    VOID* ProcessHeap;                                                      //0x30
    struct _RTL_CRITICAL_SECTION* FastPebLock;                              //0x38
    VOID* AtlThunkSListPtr;                                                 //0x40
    VOID* IFEOKey;                                                          //0x48
    union
    {
        ULONG CrossProcessFlags;                                            //0x50
        struct
        {
            ULONG ProcessInJob : 1;                                           //0x50
            ULONG ProcessInitializing : 1;                                    //0x50
            ULONG ProcessUsingVEH : 1;                                        //0x50
            ULONG ProcessUsingVCH : 1;                                        //0x50
            ULONG ProcessUsingFTH : 1;                                        //0x50
            ULONG ReservedBits0 : 27;                                         //0x50
        };
    };
    union
    {
        VOID* KernelCallbackTable;                                          //0x58
        VOID* UserSharedInfoPtr;                                            //0x58
    };
    ULONG SystemReserved[1];                                                //0x60
    ULONG AtlThunkSListPtr32;                                               //0x64
    VOID* ApiSetMap;                                                        //0x68
    ULONG TlsExpansionCounter;                                              //0x70
    VOID* TlsBitmap;                                                        //0x78
    ULONG TlsBitmapBits[2];                                                 //0x80
    VOID* ReadOnlySharedMemoryBase;                                         //0x88
    VOID* HotpatchInformation;                                              //0x90
    VOID** ReadOnlyStaticServerData;                                        //0x98
    VOID* AnsiCodePageData;                                                 //0xa0
    VOID* OemCodePageData;                                                  //0xa8
    VOID* UnicodeCaseTableData;                                             //0xb0
    ULONG NumberOfProcessors;                                               //0xb8
    ULONG NtGlobalFlag;                                                     //0xbc
    union _LARGE_INTEGER CriticalSectionTimeout;                            //0xc0
    ULONGLONG HeapSegmentReserve;                                           //0xc8
    ULONGLONG HeapSegmentCommit;                                            //0xd0
    ULONGLONG HeapDeCommitTotalFreeThreshold;                               //0xd8
    ULONGLONG HeapDeCommitFreeBlockThreshold;                               //0xe0
    ULONG NumberOfHeaps;                                                    //0xe8
    ULONG MaximumNumberOfHeaps;                                             //0xec
    VOID** ProcessHeaps;                                                    //0xf0
    VOID* GdiSharedHandleTable;                                             //0xf8
    VOID* ProcessStarterHelper;                                             //0x100
    ULONG GdiDCAttributeList;                                               //0x108
    struct _RTL_CRITICAL_SECTION* LoaderLock;                               //0x110
    ULONG OSMajorVersion;                                                   //0x118
    ULONG OSMinorVersion;                                                   //0x11c
    USHORT OSBuildNumber;                                                   //0x120
    USHORT OSCSDVersion;                                                    //0x122
    ULONG OSPlatformId;                                                     //0x124
    ULONG ImageSubsystem;                                                   //0x128
    ULONG ImageSubsystemMajorVersion;                                       //0x12c
    ULONG ImageSubsystemMinorVersion;                                       //0x130
    ULONGLONG ActiveProcessAffinityMask;                                    //0x138
    ULONG GdiHandleBuffer[60];                                              //0x140
    VOID(*PostProcessInitRoutine)();                                       //0x230
    VOID* TlsExpansionBitmap;                                               //0x238
    ULONG TlsExpansionBitmapBits[32];                                       //0x240
    ULONG SessionId;                                                        //0x2c0
    union _ULARGE_INTEGER AppCompatFlags;                                   //0x2c8
    union _ULARGE_INTEGER AppCompatFlagsUser;                               //0x2d0
    VOID* pShimData;                                                        //0x2d8
    VOID* AppCompatInfo;                                                    //0x2e0
    struct _UNICODE_STRING CSDVersion;                                      //0x2e8
    struct _ACTIVATION_CONTEXT_DATA* ActivationContextData;                 //0x2f8
    struct _ASSEMBLY_STORAGE_MAP* ProcessAssemblyStorageMap;                //0x300
    struct _ACTIVATION_CONTEXT_DATA* SystemDefaultActivationContextData;    //0x308
    struct _ASSEMBLY_STORAGE_MAP* SystemAssemblyStorageMap;                 //0x310
    ULONGLONG MinimumStackCommit;                                           //0x318
    struct _FLS_CALLBACK_INFO* FlsCallback;                                 //0x320
    struct _LIST_ENTRY FlsListHead;                                         //0x328
    VOID* FlsBitmap;                                                        //0x338
    ULONG FlsBitmapBits[4];                                                 //0x340
    ULONG FlsHighIndex;                                                     //0x350
    VOID* WerRegistrationData;                                              //0x358
    VOID* WerShipAssertPtr;                                                 //0x360
    VOID* pContextData;                                                     //0x368
    VOID* pImageHeaderHash;                                                 //0x370
    union
    {
        ULONG TracingFlags;                                                 //0x378
        struct
        {
            ULONG HeapTracingEnabled : 1;                                     //0x378
            ULONG CritSecTracingEnabled : 1;                                  //0x378
            ULONG SpareTracingBits : 30;                                      //0x378
        };
    };
} smPEB, * smPPEB;

// Used with NtQueryInformationProcess
typedef struct _smPROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PPEB PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} smPROCESS_BASIC_INFORMATION, * smPPROCESS_BASIC_INFORMATION;


class Common
{
    static HMODULE LoadNtQueryInformationProcess();
public:
    static BOOL EnableTokenPrivilage(HANDLE hProcess, LPCTSTR pszPrivilage);
    static LPVOID GetProcessBasicInformation(HANDLE hProcess);
    static LPVOID GetPebAddress(HANDLE hProcess);
    static LPVOID ExtractResource(WCHAR* resourceName);
    static LPVOID GetAllRunningProcesses(std::vector<std::pair<DWORD, WCHAR[260]>>& procList);
    static DWORD GetPidByProcessName(WCHAR* procName);
    static LPVOID ExtractResource(WCHAR* resourceName, DWORD* resourceSize);
};