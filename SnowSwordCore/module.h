#pragma once

#include <stdio.h>

/* SystemModuleInformation = 11 */
#define SystemModuleInformation 11

/* RTL_PROCESS_MODULE_INFORMATION / RTL_PROCESS_MODULES */
typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section;
    PVOID  MappedBase;
    PVOID  ImageBase;
    ULONG  ImageSize;
    ULONG  Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR  FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

/* ZwQuerySystemInformation º¯ÊýÖ¸Õë */
typedef NTSTATUS(NTAPI* pfnZwQuerySystemInformation)(
    ULONG  SystemInformationClass,
    PVOID  SystemInformation,
    ULONG  SystemInformationLength,
    PULONG ReturnLength
    );

BOOL GetKernelModulePath(PCWSTR ModuleName, PWSTR OutPath);