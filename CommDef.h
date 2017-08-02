/*++

Copyright (c) Bombs

Module Name:
	
	CommDef.h

Author  :Bombs
Time    :2014-4-29 11:40:03
Abstract:
   
	This file contains constants, structures used by other files

--*/

#ifndef _COMMDEF_H
#define _COMMDEF_H

#define TAG_STRONG_OD		'ODOD'
#define NT_DEVICE_NAME		L"\\Device\\fengyue0"
#define DOS_DEVICE_NAME		L"\\DosDevices\\fengyue0"

typedef struct _KSERVICE_TABLE_DESCRIPTOR {
	PULONG_PTR Base;
	PULONG Count;
	ULONG Limit;
	PUCHAR Number;
} KSERVICE_TABLE_DESCRIPTOR, *PKSERVICE_TABLE_DESCRIPTOR;

typedef struct _SERVICE_DESCRIPTOR_TABLE
{
	KSERVICE_TABLE_DESCRIPTOR ntoskrnl;
	KSERVICE_TABLE_DESCRIPTOR win32k;
	KSERVICE_TABLE_DESCRIPTOR Reserved1;
	KSERVICE_TABLE_DESCRIPTOR Reserved2;
}SERVICE_DESCRIPTOR_TABLE, *PSERVICE_DESCRIPTOR_TABLE;

extern PKSERVICE_TABLE_DESCRIPTOR	KeServiceDescriptorTable;
extern NTSYSAPI CCHAR KeNumberProcessors;

typedef unsigned long DWORD;

#define SOD_BLACK_PROCESS 1
#define SOD_WHITE_PROCESS 2

typedef struct _LIST_NODE
{
	HANDLE	hProcId;		
	PEPROCESS	pEProcess;
	DWORD	dwType;			// 1:black process 2:white process
	PVOID	pPool;			// used for shared memory
	PMDL	pMdl;			// used for shared memory
	PVOID	pUserAddrOfSharedMem;	// user mode address of shared memory(created by the driver and map to user mode)
}LIST_NODE, *PLIST_NODE;

extern LIST_NODE g_ProcList[100];
extern KSPIN_LOCK g_SpinLock;	

extern ULONG	g_ulBuildNum;
extern ULONG	g_ulMajorVer;
extern ULONG	g_ulMinorVer;
extern DWORD	g_dwCsrssProcId;
extern DWORD	g_dwExplorerProcId;

extern DWORD	g_dwIsSSDTHooked;
extern DWORD	g_dwIsHidenProcess;
extern DWORD	g_dwIsHidenWindow;
extern DWORD	g_dwIsProtectProcess;
extern HANDLE	g_hForegroundWindow;

extern KSERVICE_TABLE_DESCRIPTOR win32k;

extern PVOID	g_pDriverStart;
extern ULONG	g_ulDriverSize;
extern DWORD	g_dwRefCount;

extern ULONG	g_IsINT1Hooked;
extern ULONG	g_IsSupportLBR;
extern ULONG	g_IsEnableLBR;

#endif