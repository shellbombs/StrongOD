/*++

Copyright (c) Bombs

Module Name:
	
	HelperFunc.c

Author  :Bombs
Time    :2014-4-29 16:44:25
Abstract:
   
	This file contains some useful functions used by other modules of the driver

--*/
#include <ntifs.h>
#include "HelperFunc.h"
#include "DetourFunc.h"
#include <ntimage.h>

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, ProcCreateNotify)
#pragma alloc_text(PAGE, SSDTHookInit)
#pragma alloc_text(PAGE, HookSSDT)
#pragma alloc_text(PAGE, UnhookSSDT)
#pragma alloc_text(PAGE, GetFunctionIndex)
#pragma alloc_text(PAGE, GetOrigFunctionAddr)
#endif

//
// global variable for hook
//

DWORD	g_dwUserPostMessageIndex;
DWORD	g_dwOldUserPostMessageAddr;
PF_UserPostMessage pfOrigUserPostMessage;
PF_UserPostMessage pfMyUserPostMessage;

DWORD	g_dwSetInformationThreadIndex;
DWORD	g_dwOldSetInformationThreadAddr;
PF_SetInformationThread pfOrigSetInformationThread;
PF_SetInformationThread pfMySetInformationThread;

DWORD	g_dwUserBuildHwndListWin8Index;
DWORD	g_dwOldUserBuildHwndListWin8Addr;
PF_UserBuildHwndListWin8 pfOrigUserBuildHwndListWin8;
PF_UserBuildHwndListWin8 pfMyUserBuildHwndListWin8;

DWORD	g_dwCloseIndex;
DWORD	g_dwOldCloseAddr;
PF_Close	pfOrigClose;
PF_Close	pfMyClose;

DWORD	g_dwUserSetParentIndex;
DWORD	g_dwOldUserSetParentAddr;
PF_UserSetParent	pfOrigUserSetParent;
PF_UserSetParent	pfMyUserSetParent;

DWORD	g_dwUserFindWindowExIndex;
DWORD	g_dwOldUserFindWindowExAddr;
PF_UserFindWindowEx pfOrigUserFindWindowEx;
PF_UserFindWindowEx pfMyUserFindWindowEx;

DWORD	g_dwDuplicateObjectIndex;
DWORD	g_dwOldDuplicateObjectAddr;
PF_DuplicateObject	pfOrigDuplicateObject;
PF_DuplicateObject	pfMyDuplicateObject;

DWORD	g_dwCreateUserProcessIndex;
DWORD	g_dwOldCreateUserProcessAddr;
PF_CreateUserProcess pfOrigCreateUserProcess;
PF_CreateUserProcess pfMyCreateUserProcess;

DWORD	g_dwQueryObjectIndex;
DWORD	g_dwOldQueryObjectAddr;
PF_QueryObject	pfOrigQueryObject;
PF_QueryObject	pfMyQueryObject;

DWORD	g_dwQuerySystemInformationIndex;
DWORD	g_dwOldQuerySystemInformationAddr;
PF_QuerySystemInformation pfOrigQuerySystemInformation;
PF_QuerySystemInformation pfMyQuerySystemInformation;

DWORD	g_dwYieldExecutionIndex;
DWORD	g_dwOldYieldExecutionAddr;
PF_YieldExecution pfOrigYieldExecution;
PF_YieldExecution pfMyYieldExecution;

DWORD	g_dwCreateProcessIndex;
DWORD	g_dwOldCreateProcessAddr;
PF_CreateProcess pfOrigCreateProcess;
PF_CreateProcess pfMyCreateProcess;

DWORD	g_dwOpenProcessIndex;
DWORD	g_dwOldOpenProcessAddr;
PF_OpenProcess pfOrigOpenProcess;
PF_OpenProcess pfMyOpenProcess;

DWORD	g_dwUserQueryWindowIndex;
DWORD	g_dwOldUserQueryWindowAddr;
PF_UserQueryWindow pfOrigUserQueryWindow;
PF_UserQueryWindow pfMyUserQueryWindow;

DWORD	g_dwOpenThreadIndex;
DWORD	g_dwOldOpenThreadAddr;
PF_OpenThread	pfOrigOpenThread;
PF_OpenThread	pfMyOpenThread;

DWORD	g_dwUserGetForegroundWindowIndex;
DWORD	g_dwOldUserGetForegroundWindowAddr;
PF_UserGetForegroundWindow pfOrigUserGetForegroundWindow;
PF_UserGetForegroundWindow pfMyUserGetForegroundWindow;

DWORD	g_dwSetContextThreadIndex;
DWORD	g_dwOldSetContextThreadAddr;
PF_SetContextThread pfOrigSetContextThread;
PF_SetContextThread pfMySetContextThread;

DWORD	g_dwCreateProcessExIndex;
DWORD	g_dwOldCreateProcessExAddr;
PF_CreateProcessEx pfOrigCreateProcessEx;
PF_CreateProcessEx pfMyCreateProcessEx;

DWORD	g_dwUserBuildHwndListIndex;
DWORD	g_dwOldUserBuildHwndListAddr;
PF_UserBuildHwndList pfOrigUserBuildHwndList;
PF_UserBuildHwndList pfMyUserBuildHwndList;

DWORD	g_dwQueryInformationProcessIndex;
DWORD	g_dwOldQueryInformationProcessAddr;
PF_QueryInformationProcess pfOrigQueryInformationProcess;
PF_QueryInformationProcess pfMyQueryInformationProcess;


// not used
DWORD	g_dwObjectTableOffsetInEProcess = 0;
DWORD	g_dwExitTimeOffsetInEProcess = 0;
DWORD	g_dwSmssProcId = 0;

PVOID	g_Win32kBase = NULL;
ULONG	g_ulWin32kSize = 0;
PVOID	g_NtoskrnlBase = NULL;
ULONG	g_ulNtoskrnlSize = 0;
PVOID	g_pWin32kTable = NULL;
PVOID	g_pNtoskrnlTable = NULL;

LARGE_INTEGER g_liDbgCtrlRegValue = {0};
PLARGE_INTEGER g_pliDbgCtrlReg = &g_liDbgCtrlRegValue;

ULONG	g_ulOldTrap01 = 0;
char	g_OldDpl = 0;

PVOID GetSystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass)
/*++

Routine Description:

	Get system information by ZwQuerySystemInformaion 
	Return a pointer to corresponding structure
	
	Note: you must free the pool pointed by the returned pointer

--*/
{
	PVOID	pRet = NULL;
	ULONG	ulRetLen = 0;
	ULONG	ulSysInfoLen = 4096;
	NTSTATUS	status;

	do 
	{
		ulSysInfoLen *= 2;
		if(pRet != NULL)
		{
			ExFreePoolWithTag(pRet, TAG_STRONG_OD);
		}
		
		pRet = ExAllocatePoolWithTag(PagedPool, ulSysInfoLen, TAG_STRONG_OD);
		if(pRet == NULL)
		{
			break;
		}

		RtlZeroMemory(pRet, ulSysInfoLen);
		status = ZwQuerySystemInformation(SystemInformationClass,
											pRet,
											ulSysInfoLen,
											&ulRetLen);

	} while (status == STATUS_INFO_LENGTH_MISMATCH);

	if(status != STATUS_SUCCESS)
	{
		if(pRet != NULL)
		{
			ExFreePoolWithTag(pRet, TAG_STRONG_OD);
		}
		pRet = NULL;
	}

	return pRet;
}

HANDLE GetCsrssProcId()
/*++

Routine Description:

	Get the proc id of csrss.exe
	first try to get the id by "\\Windows\\ApiPort", 
	if failed, get the id by GetProcIdByName;

--*/
{
	PSYSTEM_HANDLE_INFORMATION	pSysHandleInfo;
	HANDLE	hProcId = 0;
	ULONG	i = 0;
	OBJECT_ATTRIBUTES	ObjAttr;
	CLIENT_ID	ClientId;
	HANDLE	hProcess, hObject;
	UCHAR	Buffer[0x100];
	POBJECT_NAME_INFORMATION	pObjNameInfo = (POBJECT_NAME_INFORMATION)Buffer;

	pSysHandleInfo = (PSYSTEM_HANDLE_INFORMATION)GetSystemInformation(SystemHandleInformation);
	if(pSysHandleInfo != NULL)
	{
		for(i = 0; i < pSysHandleInfo->NumberOfHandles; i++)
		{
			if(pSysHandleInfo->Handles[i].ObjectTypeIndex == 21)	// [Warning:Original code in ida ObjectTypeIndex == 18]
			{
				InitializeObjectAttributes(&ObjAttr, NULL, OBJ_KERNEL_HANDLE,
									NULL, NULL);
				ClientId.UniqueProcess = (HANDLE)pSysHandleInfo->Handles[i].ProcessId;
				ClientId.UniqueThread = 0;
				if(NT_SUCCESS(ZwOpenProcess(&hProcess, PROCESS_DUP_HANDLE,
					&ObjAttr, &ClientId)))
				{
					if(NT_SUCCESS(ZwDuplicateObject(hProcess, (HANDLE)pSysHandleInfo->Handles[i].HandleValue,
						NtCurrentProcess(), &hObject, 0, 0, DUPLICATE_SAME_ACCESS)))
					{
						if(NT_SUCCESS(ZwQueryObject(hObject, 1/*ObjectNameInformation*/, pObjNameInfo, 0x100, NULL)))
						{
							if(pObjNameInfo->Name.Buffer != 0 && 
								0 == wcsncmp(L"\\Windows\\ApiPort", pObjNameInfo->Name.Buffer, 20))
							{
								hProcId = (HANDLE)pSysHandleInfo->Handles[i].ProcessId;

								KdPrint(("GetCsrssProcId: get csrss.exe proc id by LPC Port, proc id:%d\n",
												hProcId));
							}
						}
						ZwClose(hObject);
					}
					ZwClose(hProcess);
				}
			}
		}
		ExFreePool(pSysHandleInfo);

		if(0 == hProcId)
		{
			hProcId = GetProcIdByName(L"csrss.exe");
		}
	}

	return hProcId;
}

HANDLE GetProcIdByName(wchar_t * szProcName)
/*++

Routine Description:

	Get Process id by GetSystemInformation(SystemProcessesAndThreadsInformation)

--*/
{
	HANDLE	hProcId = NULL;
	UNICODE_STRING	unProcName;
	PSYSTEM_PROCANDTHREAD_INFORMATION	pSysProcInfo = NULL;
	PSYSTEM_PROCANDTHREAD_INFORMATION	pTmp = NULL;
	
	RtlInitUnicodeString(&unProcName, szProcName);
	pSysProcInfo = (PSYSTEM_PROCANDTHREAD_INFORMATION)GetSystemInformation(SystemProcessesAndThreadsInformation);
	if(pSysProcInfo != NULL)
	{
		pTmp = pSysProcInfo;
		while(1) // [Warning: some differences with ida code]
		{
			if(0 == RtlCompareUnicodeString(&pTmp->ProcessName, &unProcName, TRUE))
			{
				hProcId = (HANDLE)pTmp->ProcessId;
				break;
			}

			if(pTmp->NextEntryDelta == 0)
			{
				break;
			}

			pTmp = (PSYSTEM_PROCANDTHREAD_INFORMATION)((char *)pTmp + pTmp->NextEntryDelta);
		}

		ExFreePoolWithTag(pSysProcInfo, TAG_STRONG_OD);
	}

	return hProcId;
}

PVOID GetServiceDescriptorTableShadowAddr()
/*++

Routine Description:

	The first service_table_descriptor of KeServiceDescriptorTable
	is the same with that of KeServiceDescriptorTableShadow, and the
	unducumented routine KeAddSystemServiceTalbe references both of them.
	so we can search the memory of KeAddSystemServiceTable to get the 
	correct addr of KeServiceDescriptorTableShadow.

	note: use an exception handler when searching memory

--*/
{
	int i = 0;
	ULONG	Addr = 0;
	PVOID	pRet = NULL;

	while(i < 0x1000)
	{
		__try
		{
			Addr = *(PULONG)((PUCHAR)KeAddSystemServiceTable + i);
			if(MmIsAddressValid((PVOID)Addr) &&
				Addr != (ULONG)KeServiceDescriptorTable &&
				0 == memcmp((PVOID)Addr, KeServiceDescriptorTable, 16))
			{
				pRet = (PVOID)Addr;
				break;
			}

		}__except(EXCEPTION_EXECUTE_HANDLER)
		{
			pRet = NULL;
		}

		i++;
	}

	return pRet;
}

VOID ProcCreateNotify(
					  IN HANDLE  ParentId,
					  IN HANDLE  ProcessId,
					  IN BOOLEAN  Create
					  )
/*++

Routine Description:

	Process create notify callback, del proc from proc list

--*/
{
	NTSTATUS status;
	PEPROCESS pEProcess;
	
	if(!Create)
	{
		status = PsLookupProcessByProcessId(ProcessId, &pEProcess);
		if(NT_SUCCESS(status))
		{
			if(IsProcessInList(pEProcess, 0, SOD_WHITE_PROCESS))
			{
				DelProcInfoFromList(pEProcess, 0, SOD_WHITE_PROCESS);
				if(0 == GetProcCount(SOD_WHITE_PROCESS))
				{
					UnhookSSDT();
				}
			}
			
			if(IsProcessInList(pEProcess, 0, SOD_BLACK_PROCESS))
			{
				DelProcInfoFromList(pEProcess, 0, SOD_BLACK_PROCESS);
				if(0 == GetProcCount(SOD_BLACK_PROCESS))
				{
					UnhookINT1();
				}
			}
			
			ObDereferenceObject(pEProcess);
		}
	}
}

ULONG g_ServiceTableOffsetInKThread = 0;

VOID SSDTHookInit()
/*++

Routine Description:

	init global variables, function index of ssdt table, original function address, etc.

--*/
{
	NTSTATUS	status;
	PKTHREAD	pThread = NULL;
	int i = 0;
	UNICODE_STRING	unModuleName;
	PEPROCESS	pEprocessOfCsrss;
	KAPC_STATE	ApcState;
	
	if(KeServiceDescriptorTable != NULL)
	{
		pThread = KeGetCurrentThread();
		for(i = 0; i < 336; i++)
		{
			if(*(PULONG)((PUCHAR)pThread + i) == (ULONG)KeServiceDescriptorTable)
			{
				g_ServiceTableOffsetInKThread = i;
				break;
			}
		}
	}
	
	RtlInitUnicodeString(&unModuleName, L"\\SystemRoot\\system32\\ntdll.dll");
	g_dwSetContextThreadIndex = GetFunctionIndex("NtSetContextThread", &unModuleName);
	pfMySetContextThread = MySetContextThread;
	pfOrigSetContextThread = GetOrigFunctionAddr(g_dwSetContextThreadIndex, 0);
	KdPrint(("SSDTHookInit:g_dwSetContextThreadIndex[%d], pfOrigSetContextThread[%08X]\n", 
				g_dwSetContextThreadIndex, pfOrigSetContextThread));
	
	g_dwQuerySystemInformationIndex = GetFunctionIndex("NtQuerySystemInformation", &unModuleName);
	pfMyQuerySystemInformation = MyQuerySystemInformation;
	pfOrigQuerySystemInformation = GetOrigFunctionAddr(g_dwQuerySystemInformationIndex, 0);
	KdPrint(("SSDTHookInit:g_dwQuerySystemInformationIndex[%d], pfOrigQuerySystemInformation[%08X]\n", 
		g_dwQuerySystemInformationIndex, pfOrigQuerySystemInformation));

	g_dwQueryObjectIndex = GetFunctionIndex("NtQueryObject", &unModuleName);
	pfMyQueryObject = MyQueryObject;
	pfOrigQueryObject = GetOrigFunctionAddr(g_dwQueryObjectIndex, 0);
	KdPrint(("SSDTHookInit:g_dwQueryObjectIndex[%d], pfOrigQueryObject[%08X]\n", 
		g_dwQueryObjectIndex, pfOrigQueryObject));

	g_dwYieldExecutionIndex = GetFunctionIndex("NtYieldExecution", &unModuleName);
	pfMyYieldExecution = MyYieldExecution;
	pfOrigYieldExecution = GetOrigFunctionAddr(g_dwYieldExecutionIndex, 0);
	KdPrint(("SSDTHookInit:g_dwYieldExecutionIndex[%d], pfOrigYieldExecution[%08X]\n", 
		g_dwYieldExecutionIndex, pfOrigYieldExecution));

	g_dwOpenProcessIndex = GetFunctionIndex("NtOpenProcess", &unModuleName);
	pfMyOpenProcess = MyOpenProcess;
	pfOrigOpenProcess = GetOrigFunctionAddr(g_dwOpenProcessIndex, 0);
	KdPrint(("SSDTHookInit:g_dwOpenProcessIndex[%d], pfOrigOpenProcess[%08X]\n", 
		g_dwOpenProcessIndex, pfOrigOpenProcess));

	g_dwOpenThreadIndex = GetFunctionIndex("NtOpenThread", &unModuleName);
	pfMyOpenThread = MyOpenThread;
	pfOrigOpenThread = GetOrigFunctionAddr(g_dwOpenThreadIndex, 0);
	KdPrint(("SSDTHookInit:g_dwOpenThreadIndex[%d], pfOrigOpenThread[%08X]\n", 
		g_dwOpenThreadIndex, pfOrigOpenThread));

	g_dwSetInformationThreadIndex = GetFunctionIndex("NtSetInformationThread", &unModuleName);
	pfMySetInformationThread = MySetInformationThread;
	pfOrigSetInformationThread = GetOrigFunctionAddr(g_dwSetInformationThreadIndex, 0);
	KdPrint(("SSDTHookInit:g_dwSetInformationThreadIndex[%d], pfOrigSetInformationThread[%08X]\n", 
		g_dwSetInformationThreadIndex, pfOrigSetInformationThread));
		
	g_dwQueryInformationProcessIndex = GetFunctionIndex("NtQueryInformationProcess", &unModuleName);
	pfMyQueryInformationProcess = MyQueryInformationProcess;
	pfOrigQueryInformationProcess = GetOrigFunctionAddr(g_dwQueryInformationProcessIndex, 0);
	KdPrint(("SSDTHookInit:g_dwQueryInformationProcessIndex[%d], pfOrigQueryInformationProcess[%08X]\n", 
		g_dwQueryInformationProcessIndex, pfOrigQueryInformationProcess));

	g_dwCloseIndex = GetFunctionIndex("NtClose", &unModuleName);
	pfMyClose = MyClose;
	pfOrigClose = GetOrigFunctionAddr(g_dwCloseIndex, 0);
	KdPrint(("SSDTHookInit:g_dwCloseIndex[%d], pfOrigClose[%08X]\n", 
		g_dwCloseIndex, pfOrigClose));

	g_dwDuplicateObjectIndex = GetFunctionIndex("NtDuplicateObject", &unModuleName);
	pfMyDuplicateObject = MyDuplicateObject;
	pfOrigDuplicateObject = GetOrigFunctionAddr(g_dwDuplicateObjectIndex, 0);
	KdPrint(("SSDTHookInit:g_dwDuplicateObjectIndex[%d], pfOrigDuplicateObject[%08X]\n", 
		g_dwDuplicateObjectIndex, pfOrigDuplicateObject));


	if(g_ulMajorVer >= 6)
	{
		g_dwCreateUserProcessIndex = GetFunctionIndex("NtCreateUserProcess", &unModuleName);
		pfMyCreateUserProcess = MyCreateUserProcess;
		pfOrigCreateUserProcess = GetOrigFunctionAddr(g_dwCreateUserProcessIndex, 0);
	}
	else
	{
		g_dwCreateProcessIndex = GetFunctionIndex("NtCreateProcess", &unModuleName);
		pfMyCreateProcess = MyCreateProcess;
		pfOrigCreateUserProcess = GetOrigFunctionAddr(g_dwCreateProcessIndex, 0);
		
		g_dwCreateProcessExIndex = GetFunctionIndex("NtCreateProcessEx", &unModuleName);
		pfMyCreateProcessEx = MyCreateProcessEx;
		pfOrigCreateProcessEx = GetOrigFunctionAddr(g_dwCreateProcessExIndex, 0);
	}

	pfMyUserPostMessage = MyUserPostMessage;
	g_dwOldUserPostMessageAddr = 0;
	g_dwUserPostMessageIndex = -1;

	pfMyUserQueryWindow = MyUserQueryWindow;
	g_dwOldUserQueryWindowAddr = 0;
	g_dwUserQueryWindowIndex = -1;

	pfMyUserBuildHwndList = MyUserBuildHwndList;
	g_dwOldUserBuildHwndListAddr = 0;
	g_dwUserBuildHwndListIndex = -1;

	pfMyUserBuildHwndListWin8 = MyUserBuildHwndListWin8;
	g_dwOldUserBuildHwndListWin8Addr = 0;
	g_dwUserBuildHwndListWin8Index = -1;

	pfMyUserFindWindowEx = MyUserFindWindowEx;
	g_dwOldUserFindWindowExAddr = 0;
	g_dwUserFindWindowExIndex = -1;

	pfMyUserGetForegroundWindow = MyUserGetForegroundWindow;
	g_dwOldUserGetForegroundWindowAddr =  0;
	g_dwUserGetForegroundWindowIndex = -1;

	pfMyUserSetParent = MyUserSetParent;
	g_dwOldUserSetParentAddr = 0;
	g_dwUserSetParentIndex = -1;


	if(g_ulMajorVer == 5 && g_ulMinorVer == 0)
	{
		// win2000
		g_dwUserQueryWindowIndex = 466;
		g_dwUserBuildHwndListIndex = 302;
		g_dwUserFindWindowExIndex = 368;
		g_dwUserGetForegroundWindowIndex = 393;
		g_dwUserSetParentIndex = 510;
		g_dwUserPostMessageIndex = 459;
		g_dwObjectTableOffsetInEProcess = 296;
		g_dwExitTimeOffsetInEProcess = 144;
		g_dwSmssProcId = (DWORD)GetProcIdByName(L"smss.exe");
	}
	else if(g_ulMajorVer == 5 && g_ulMinorVer == 1)
	{
		// winxp
		g_dwUserQueryWindowIndex = 483;
		g_dwUserBuildHwndListIndex = 312;
		g_dwUserFindWindowExIndex = 378;
		g_dwUserGetForegroundWindowIndex = 404;
		g_dwUserSetParentIndex = 529;
		g_dwUserPostMessageIndex = 475;
		g_dwObjectTableOffsetInEProcess = 196;
		g_dwExitTimeOffsetInEProcess = 120;
	}
	else if(g_ulMajorVer == 5 && g_ulMinorVer == 2)
	{
		// win2003
		g_dwUserQueryWindowIndex = 481;
		g_dwUserBuildHwndListIndex = 311;
		g_dwUserFindWindowExIndex = 377;
		g_dwUserGetForegroundWindowIndex = 403;
		g_dwUserSetParentIndex = 526;
		g_dwUserPostMessageIndex = 474;
		g_dwObjectTableOffsetInEProcess = 212;
		g_dwExitTimeOffsetInEProcess = 136;
	}
	else if(g_ulMajorVer == 6 && g_ulMinorVer == 0)
	{
		// winvista
		g_dwUserQueryWindowIndex = 504;
		g_dwUserBuildHwndListIndex = 322;
		g_dwUserFindWindowExIndex = 391;
		g_dwUserGetForegroundWindowIndex = 418;
		g_dwUserSetParentIndex = 550;
		g_dwUserPostMessageIndex = 497;
		g_dwObjectTableOffsetInEProcess = 0;
		g_dwExitTimeOffsetInEProcess = 0;
	}
	else if(g_ulMajorVer == 6 && g_ulMinorVer == 1 && g_ulBuildNum >= 0x1DB0)
	{
		// win7
		g_dwUserQueryWindowIndex = 515;
		g_dwUserBuildHwndListIndex = 323;
		g_dwUserFindWindowExIndex = 396;
		g_dwUserGetForegroundWindowIndex = 423;
		g_dwUserSetParentIndex = 560;
		g_dwUserPostMessageIndex = 508;
		g_dwObjectTableOffsetInEProcess = 244;
		g_dwExitTimeOffsetInEProcess = 168;
	}
	else if(g_ulMajorVer == 6 && g_ulMinorVer == 2 && g_ulBuildNum >= 0x23F0)
	{
		// win8
		g_dwUserQueryWindowIndex = 482;
		g_dwUserBuildHwndListIndex = -1;
		g_dwUserBuildHwndListWin8Index = 360;
		g_dwUserFindWindowExIndex = 459;
		g_dwUserGetForegroundWindowIndex = 429;
		g_dwUserSetParentIndex = 590;
		g_dwUserPostMessageIndex = 490;
		g_dwObjectTableOffsetInEProcess = 0;
		g_dwExitTimeOffsetInEProcess = 696;
	}
	else
	{
		// unknown os ver
		g_dwUserQueryWindowIndex = -1;
		g_dwUserBuildHwndListIndex = -1;
		g_dwUserBuildHwndListWin8Index = -1;
		g_dwUserFindWindowExIndex = -1;
		g_dwUserGetForegroundWindowIndex = -1;
		g_dwUserSetParentIndex = -1;
		g_dwUserPostMessageIndex = -1;
		g_dwObjectTableOffsetInEProcess = 0;
		g_dwExitTimeOffsetInEProcess = 0;
	}

	if(g_dwCsrssProcId != 0)
	{
		status = PsLookupProcessByProcessId((HANDLE)g_dwCsrssProcId, &pEprocessOfCsrss);
		if(NT_SUCCESS(status))
		{
			KeStackAttachProcess(pEprocessOfCsrss, &ApcState);
			pfOrigUserQueryWindow = GetOrigFunctionAddr(g_dwUserQueryWindowIndex, 1);
			KdPrint(("SSDTHookInit:g_dwUserQueryWindowIndex[%d], pfOrigUserQueryWindow[%08X]\n", 
				g_dwUserQueryWindowIndex, pfOrigUserQueryWindow));

			pfOrigUserBuildHwndList = GetOrigFunctionAddr(g_dwUserBuildHwndListIndex, 1);
			KdPrint(("SSDTHookInit:g_dwUserBuildHwndListIndex[%d], pfOrigUserBuildHwndList[%08X]\n", 
				g_dwUserBuildHwndListIndex, pfOrigUserBuildHwndList));

			pfOrigUserBuildHwndListWin8 = GetOrigFunctionAddr(g_dwUserBuildHwndListWin8Index, 1);
			KdPrint(("SSDTHookInit:g_dwUserBuildHwndListWin8Index[%d], pfOrigUserBuildHwndListWin8[%08X]\n", 
				g_dwUserBuildHwndListWin8Index, pfOrigUserBuildHwndListWin8));

			pfOrigUserFindWindowEx = GetOrigFunctionAddr(g_dwUserFindWindowExIndex, 1);
			KdPrint(("SSDTHookInit:g_dwUserFindWindowExIndex[%d], pfOrigUserFindWindowEx[%08X]\n", 
				g_dwUserFindWindowExIndex, pfOrigUserFindWindowEx));

			pfOrigUserGetForegroundWindow = GetOrigFunctionAddr(g_dwUserGetForegroundWindowIndex, 1);
			KdPrint(("SSDTHookInit:g_dwUserGetForegroundWindowIndex[%d], pfOrigUserGetForegroundWindow[%08X]\n", 
				g_dwUserGetForegroundWindowIndex, pfOrigUserGetForegroundWindow));

			pfOrigUserSetParent = GetOrigFunctionAddr(g_dwUserSetParentIndex, 1);
			KdPrint(("SSDTHookInit:g_dwUserSetParentIndex[%d], pfOrigUserSetParent[%08X]\n", 
				g_dwUserSetParentIndex, pfOrigUserSetParent));

			pfOrigUserPostMessage = GetOrigFunctionAddr(g_dwUserPostMessageIndex, 1);
			KdPrint(("SSDTHookInit:g_dwUserPostMessageIndex[%d], pfOrigUserPostMessage[%08X]\n", 
				g_dwUserPostMessageIndex, pfOrigUserPostMessage));

			KeUnstackDetachProcess(&ApcState);
			ObDereferenceObject(pEprocessOfCsrss);
		}
	}
}

BOOLEAN IsProcessInList(PEPROCESS pEProcess,
					ULONG hProcId,
					DWORD dwType)
/*++

Routine Description:

	Check if a process is in the proc list by its EPROCESS or ProcId,
	dwType == 1(Black process) dwType == 2(White process)

--*/
{
	BOOLEAN	bRet = FALSE;
	KIRQL	OldIrql;
	int	i = 0, j = 0;
	PEPROCESS pEProcessTmp;

	if( (NULL != pEProcess || 0 != hProcId) &&
		0 != dwType)
	{
		if(NULL != pEProcess)
		{
			KeAcquireSpinLock(&g_SpinLock, &OldIrql);
			for(i = 0; i < 100; i++)
			{
				if(g_ProcList[i].pEProcess == pEProcess &&
					g_ProcList[i].dwType == dwType)
				{
					bRet = TRUE;
					break;
				}
			}
			KeReleaseSpinLock(&g_SpinLock, OldIrql);
		}
		else if(NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)hProcId, &pEProcessTmp)))
		{
			KeAcquireSpinLock(&g_SpinLock, &OldIrql);
			for(j = 0; j < 100; j++)
			{
				if((ULONG)g_ProcList[j].hProcId == hProcId)	
				{
					bRet = TRUE;
					break;
				}
			}
			KeReleaseSpinLock(&g_SpinLock, OldIrql);
			ObDereferenceObject(pEProcessTmp);
		}
	}

	return bRet;
}
					
PLIST_NODE GetProcInfoFromList(PEPROCESS pEProcess, ULONG hProcId)
/*++

Routine Description:

	Get proc info from the proc list by its EPROCESS or ProcId

--*/
{
	KIRQL	OldIrql;
	PVOID	pRet = NULL;
	int	i = 0, j = 0;

	if(NULL != pEProcess || 0 != hProcId)
	{
		KeAcquireSpinLock(&g_SpinLock, &OldIrql);
		if(NULL != pEProcess)
		{
			for(i = 0; i < 100; i++)
			{
				if(g_ProcList[i].pEProcess == pEProcess)
				{
					pRet = &g_ProcList[i];
					break;
				}
			}
		}
		else if(0 != hProcId)
		{
			for(j = 0; j < 100; j++)
			{
				if((ULONG)g_ProcList[j].hProcId == hProcId)
				{
					pRet = &g_ProcList[j];
					break;
				}
			}
		}
		
		KeReleaseSpinLock(&g_SpinLock, OldIrql);
	}

	return pRet;
}

PMDL AllocateAndBuildMdl(PVOID pBuffer, ULONG ulLen)
/*++

Routine Description:

	Allocate and build a mdl for pBuffer.

--*/
{
	PMDL	pRet = NULL;

	pRet = IoAllocateMdl(pBuffer, ulLen, FALSE, FALSE, NULL);
	if(pRet != NULL)
	{
		MmBuildMdlForNonPagedPool(pRet);
	}

	return pRet;
}

PVOID MapSharedMemory(PMDL pMdl, PEPROCESS pEProcess)
/*++

Routine Description:

Map the physical pages that are described by the pMdl to
a user mode address

--*/
{
	PVOID	pRet = NULL;

	if(KeGetCurrentIrql() <= APC_LEVEL)
	{
		__try
		{
			pRet = MmMapLockedPagesSpecifyCache(pMdl, UserMode, MmNonCached, NULL, 0, NormalPagePriority);

		}__except(EXCEPTION_EXECUTE_HANDLER)
		{
			pRet = NULL;
		}
	}

	return pRet;
}

BOOLEAN CreateSharedMemory(LIST_NODE * pNode)
/*++

Routine Description:

	Create shared memory and map it to a user mode address

--*/
{
	BOOLEAN	bRet = FALSE;
	KAPC_STATE ApcState;

	if(pNode->dwType == 1)
	{
		KeStackAttachProcess(pNode->pEProcess, &ApcState);
		pNode->pPool = ExAllocatePoolWithTag(NonPagedPool, 0x1000, TAG_STRONG_OD);
		if(pNode->pPool != NULL)
		{
			pNode->pMdl = AllocateAndBuildMdl(pNode->pPool, 0x1000);
			if(pNode->pMdl != NULL)
			{
				pNode->pUserAddrOfSharedMem = MapSharedMemory(pNode->pMdl, pNode->pEProcess);
				if(pNode->pUserAddrOfSharedMem != NULL)
				{
					bRet = TRUE;
				}
				else
				{
					IoFreeMdl(pNode->pMdl);
					pNode->pMdl = NULL;
					ExFreePoolWithTag(pNode->pPool, TAG_STRONG_OD);
					pNode->pPool = NULL;
				}
			}
			else
			{
				ExFreePoolWithTag(pNode->pPool, TAG_STRONG_OD);
				pNode->pPool = NULL;
			}
		}
		KeUnstackDetachProcess(&ApcState);
	}

	return bRet;
}

BOOLEAN UnmapSharedMemory(PMDL pMdl, PVOID pMapAddr)
/*++

Routine Description:

	release a mapping set up by a preceding call to MmMapXXX

--*/
{
	BOOLEAN	bRet = FALSE;

	if(KeGetCurrentIrql() < DISPATCH_LEVEL)
	{
		__try
		{
			MmUnmapLockedPages(pMapAddr, pMdl);
			bRet = TRUE;
		}__except(EXCEPTION_EXECUTE_HANDLER)
		{
			bRet = FALSE;
		}
	}

	return bRet;
}

BOOLEAN ClearSharedMemory(LIST_NODE *pNode)
/*++

Routine Description:

	Clear shared memory when process exit

--*/
{
	BOOLEAN	bRet = FALSE;
	KAPC_STATE	ApcState;

	if(pNode->dwType == 1)
	{			
		KeStackAttachProcess(pNode->pEProcess, &ApcState);
		__try
		{
			UnmapSharedMemory(pNode->pMdl, pNode->pUserAddrOfSharedMem);
			IoFreeMdl(pNode->pMdl);
			ExFreePoolWithTag(pNode->pPool, TAG_STRONG_OD);

			bRet = TRUE;
		}__except(EXCEPTION_EXECUTE_HANDLER)
		{
			bRet = FALSE;
		}
		KeUnstackDetachProcess(&ApcState);
	}

	return bRet;
}

ULONG AddProcInfoToList(PEPROCESS pEProcess, ULONG hProcId, DWORD dwType)
/*++

Routine Description:

	Add proc info to the proc list

--*/
{
	ULONG	ulRet = 0;
	KIRQL OldIrql;
	int	i = 0;
	PEPROCESS pEProcessTmp = NULL;

	if(pEProcess != NULL || hProcId != 0)
	{
		if(0 != dwType)
		{
			KeAcquireSpinLock(&g_SpinLock, &OldIrql);
			for(i = 0; i < 100; i++)
			{
				if(g_ProcList[i].pEProcess != pEProcess ||
					(ULONG)g_ProcList[i].hProcId != hProcId)	
				{
					if(g_ProcList[i].pEProcess == NULL &&
						g_ProcList[i].hProcId == NULL)
					{
						g_ProcList[i].dwType = dwType;
						g_ProcList[i].hProcId = (HANDLE)hProcId;
						if(pEProcess != NULL)
						{
							g_ProcList[i].pEProcess = pEProcess;
						}

						KdPrint(("AddProcInfoToList: add proc to list, EProcess[%08X], ProcId[%d], dwType[%d]\n",
							pEProcess, hProcId, dwType));
						break;
					}
				}
			}
			KeReleaseSpinLock(&g_SpinLock, OldIrql);

			if(pEProcess == NULL &&
				NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)hProcId, &pEProcessTmp)))
			{
				g_ProcList[i].pEProcess = pEProcessTmp;
				ObDereferenceObject(pEProcessTmp);
			}

			if( dwType != 1 || CreateSharedMemory(&g_ProcList[i]))
			{
				ulRet = 1;
			}
			else
			{
				ulRet = -1;	// black process && create shared memory failed!
			}
		}
	}

	return ulRet;
}

BOOLEAN DelProcInfoFromList(PEPROCESS pEProcess, ULONG hProcId, DWORD dwType)
/*++

Routine Description:

	del proc info from the proc list

--*/
{
	BOOLEAN	bRet = FALSE;
	LIST_NODE	Node;
	KIRQL OldIrql;
	int	i = 0, j = 0;

	if(pEProcess != NULL || hProcId != 0)
	{
		if(0 != dwType)
		{
			KeAcquireSpinLock(&g_SpinLock, &OldIrql);
			for(i = 0; i < 100; i++)
			{
				if(pEProcess != NULL &&
					g_ProcList[i].pEProcess == pEProcess &&
					g_ProcList[i].dwType == dwType)
				{
					RtlCopyMemory(&Node, &g_ProcList[i], sizeof(LIST_NODE));
					for(j = i; j < 99; j++)
					{
						if(g_ProcList[j + 1].pEProcess != NULL)
						{
							RtlCopyMemory(&g_ProcList[j], &g_ProcList[j + 1], sizeof(LIST_NODE));
						}
						else
						{
							break;
						}
					}
					RtlZeroMemory(&g_ProcList[j], sizeof(LIST_NODE));
					bRet = TRUE;

					KdPrint(("DelProcInfoFromList: del proc from list by EProcess, EProcess[%08X], ProcId[%d], dwType[%d]\n",
						pEProcess, hProcId, dwType));
					break;
				}
				else if(hProcId != 0 &&
					(ULONG)g_ProcList[i].hProcId == hProcId &&	
					g_ProcList[i].dwType == dwType)
				{
					RtlCopyMemory(&Node, &g_ProcList[i], sizeof(LIST_NODE));
					for(j = i; j < 99; j++)
					{
						if(g_ProcList[j + 1].pEProcess != NULL)
						{
							RtlCopyMemory(&g_ProcList[j], &g_ProcList[j + 1], sizeof(LIST_NODE));
						}
						else
						{
							break;
						}
					}
					RtlZeroMemory(&g_ProcList[j], sizeof(LIST_NODE));
					bRet = TRUE;

					KdPrint(("DelProcInfoFromList: del proc from list by ProcId, EProcess[%08X], ProcId[%d], dwType[%d]\n",
						pEProcess, hProcId, dwType));
					break;
				}
			}
			KeReleaseSpinLock(&g_SpinLock, OldIrql);
			if(Node.dwType == 1)
			{
				ClearSharedMemory(&Node);
			}
		}
	}

	return bRet;
}

ULONG GetProcCount(DWORD dwType)
/*++

Routine Description:

	Get proc count from the proc list
	dwType == 1: get black process count
	dwType == 2: get white process count

--*/
{
	KIRQL	OldIrql;
	ULONG	ulRet = 0;
	int	i = 0;

	if(0 != dwType)
	{
		KeAcquireSpinLock(&g_SpinLock, &OldIrql);
		for(i = 0; i < 100; i++)
		{
			if(g_ProcList[i].pEProcess != NULL ||
				g_ProcList[i].hProcId != NULL)
			{
				if(g_ProcList[i].dwType == dwType)
				{
					ulRet++;
				}
			}
		}
		KeReleaseSpinLock(&g_SpinLock, OldIrql);
	}

	return ulRet;
}

int GetFunctionIndex(char * szFunctionName, PUNICODE_STRING punModuleName)
/*++

Routine Description:

	Get the function index of ssdt table by analyzing the ntdll.dll on the disk

--*/
{
	OBJECT_ATTRIBUTES	ObjAttr;
	HANDLE	hFile = NULL;
	HANDLE	hSection = NULL;
	PUCHAR	pImageBase = NULL;
	NTSTATUS	status;
	IO_STATUS_BLOCK IoStatus;
	int iRet = -1;
	SIZE_T size = 0;
	PIMAGE_DOS_HEADER pImageDosHeader = NULL;
	PIMAGE_NT_HEADERS pImageNtHeaders = NULL;
	PIMAGE_OPTIONAL_HEADER32 pImageOptionalHeader = NULL;
	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = NULL;
	PUCHAR pAddressOfFunctions = NULL;
	PUCHAR pAddressOfNames = NULL;
	PUCHAR pAddressOfNameOrdinals = NULL;
	ULONG ulBase;
	ANSI_STRING anFuncName;
	ULONG i = 0;
	char * szTmp;
	ANSI_STRING anTmp;
	ULONG ulFuncAddr;
	ULONG ulFuncOrdinal;

	InitializeObjectAttributes(&ObjAttr, punModuleName, 
						OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

	status = ZwOpenFile(&hFile, FILE_EXECUTE | SYNCHRONIZE, &ObjAttr,
							&IoStatus, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);
	
	if(NT_SUCCESS(status))
	{
		ObjAttr.ObjectName = NULL;
		status = ZwCreateSection(&hSection, SECTION_ALL_ACCESS, &ObjAttr, 0, PAGE_EXECUTE,
							0x1000000/*SEC_IMAGE*/, hFile);

		if(NT_SUCCESS(status))
		{
			ZwMapViewOfSection(hSection, ZwCurrentProcess(), &pImageBase,
						0, 0x3E8, 0, &size, ViewShare, MEM_TOP_DOWN, PAGE_READWRITE);

			ZwClose(hFile);

			pImageDosHeader = (PIMAGE_DOS_HEADER)pImageBase;
			pImageNtHeaders = (PIMAGE_NT_HEADERS)(pImageBase + pImageDosHeader->e_lfanew);
			pImageOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)&pImageNtHeaders->OptionalHeader;
			pImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(pImageBase + pImageOptionalHeader->DataDirectory[0].VirtualAddress);
			pAddressOfFunctions = pImageBase + pImageExportDirectory->AddressOfFunctions;
			pAddressOfNames = pImageBase + pImageExportDirectory->AddressOfNames;
			pAddressOfNameOrdinals = pImageBase + pImageExportDirectory->AddressOfNameOrdinals;
			ulBase = pImageExportDirectory->Base;

			RtlInitString(&anFuncName, szFunctionName);
			for (i = 0; i < pImageExportDirectory->NumberOfFunctions; i++)
			{
				szTmp = pImageBase + *(PULONG)(pAddressOfNames + i*4);
				RtlInitString(&anTmp, szTmp);
				if(RtlCompareString(&anTmp, &anFuncName, TRUE) == 0)
				{
					ulFuncOrdinal = *(USHORT *)(pAddressOfNameOrdinals + i*2);
					// ulFuncOrdinal = ulFuncOrdinal + ulBase - 1;	// [Warning:]
					ulFuncAddr = (ULONG)(pImageBase + *(PULONG)(pAddressOfFunctions + 4 * ulFuncOrdinal));
					iRet = *(PULONG)(ulFuncAddr + 1);
					break;
				}
			}
			ZwClose(hSection);
			ZwUnmapViewOfSection(ZwCurrentProcess(), pImageBase);
		}
		else
		{
			ZwClose(hFile);
		}
	}

	return iRet;
}

char * GetModuleNameFromPath(PANSI_STRING pModulePath)
/*++

Routine Description:

	Get name from path

--*/
{
	char * pRet = NULL;
	char * pBufferEnd = NULL;

	if(pModulePath->Length != 0)
	{
		pBufferEnd = &pModulePath->Buffer[pModulePath->Length];
		while(pBufferEnd != pModulePath->Buffer)
		{
			pBufferEnd--;
			if(*pBufferEnd == '\\')
			{
				pBufferEnd++;
				break;
			}
		}
		pRet = pBufferEnd;
	}

	return pRet;
}

NTSTATUS GetNtoskrnlInfo(char * szModuleName, PULONG pulModuleSize, PVOID * pModuleBase)
/*++

Routine Description:

	Get the nt kernel file(ntoskrnl.exe) info by ZwQuerySystemInformation
	szModuleName:   [out] the kernel module name
	pulModuleSize:  [out] the kernel module size
	pModuleBase:    [out] the kernel module base addr

--*/
{
	NTSTATUS status;
	PSYSTEM_MODULE_INFORMATION	pSmi = NULL;
	ULONG	ulReturnLen;
	ANSI_STRING anModulePath;
	char * pName;

	status = ZwQuerySystemInformation(SystemModuleInformation, pSmi, 0, &ulReturnLen);
	if(status == STATUS_INFO_LENGTH_MISMATCH)
	{
		pSmi = (PSYSTEM_MODULE_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, ulReturnLen, TAG_STRONG_OD);
		status = ZwQuerySystemInformation(SystemModuleInformation, pSmi, ulReturnLen, 0);
	}

	if(NT_SUCCESS(status))
	{
		*pulModuleSize = pSmi->Modules[0].ImageSize;
		*pModuleBase = pSmi->Modules[0].ImageBaseAddress;
		RtlInitAnsiString(&anModulePath, pSmi->Modules[0].Name);
		pName = GetModuleNameFromPath(&anModulePath);
		if(pName != NULL)
		{
			strncpy(szModuleName, pName, strlen(pName) + 1);
		}
		else
		{
			status = STATUS_UNSUCCESSFUL;
		}
	}

	if(pSmi != NULL)
	{
		ExFreePoolWithTag(pSmi, TAG_STRONG_OD);
		pSmi = NULL;
	}
	
	return status;
}

PVOID GetProcAddressKernelMode(PVOID pModuleBase, char * szFuncName)
/*++

Routine Description:

	Like user mode function GetProcAddress, GetProcAddressKernelMode can get 
	the function address by function name or function ordinal

--*/
{
	PVOID	pRet = NULL;
	PIMAGE_DOS_HEADER	pImageDosHeader = (PIMAGE_DOS_HEADER)pModuleBase;
	PIMAGE_NT_HEADERS	pImageNtHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)pImageDosHeader + pImageDosHeader->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)pImageDosHeader + 
											pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
	PUCHAR	pAddressOfNames = NULL;
	ULONG i = 0;
	USHORT	uFuncOrdinal = 0;
	
	if(pImageNtHeaders->OptionalHeader.DataDirectory[0].Size != 0 &&
		pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress != 0)
	{
		if((ULONG)szFuncName >= 0x10000)
		{
			// get proc addr by name
			pAddressOfNames = (PUCHAR)pImageDosHeader + pImageExportDirectory->AddressOfNames;
			for(i = 0; i < pImageExportDirectory->NumberOfNames; i++)
			{
				if(0 == strcmp(szFuncName, (PUCHAR)pImageDosHeader + *(PULONG)(pAddressOfNames + 4*i) ))
				{
					uFuncOrdinal = *(USHORT *)(pImageExportDirectory->AddressOfNameOrdinals + 2 * i + 
										(PUCHAR)pImageDosHeader);
					pRet = (PVOID)((PUCHAR)pImageDosHeader + 
						*(PULONG_PTR)((PUCHAR)pImageDosHeader + pImageExportDirectory->AddressOfFunctions + 4 * uFuncOrdinal));
				}
			}
		}
		else
		{
			// get proc addr by ordinal
			if((ULONG)szFuncName < pImageExportDirectory->Base + pImageExportDirectory->NumberOfFunctions ||
				(ULONG)szFuncName >= pImageExportDirectory->Base)
			{
				uFuncOrdinal = (USHORT)((ULONG)szFuncName - pImageExportDirectory->Base);

				pRet = (PVOID)((PUCHAR)pImageDosHeader + 
					*(PULONG_PTR)((PUCHAR)pImageDosHeader + pImageExportDirectory->AddressOfFunctions + 4 * uFuncOrdinal));
			}
		}
	}

	return pRet;
}


typedef struct _IMAGE_FIXUP_ENTRY{
	USHORT offset:12;
	USHORT type:4;
}IMAGE_FIXUP_ENTRY, *PIMAGE_FIXUP_ENTRY;

ULONG GetFuncOffsetInModule(PUNICODE_STRING punModuleName, DWORD dwType, DWORD dwFuncIndex)
/*++

Routine Description:

	Get the function offset in module;
	dwType == 0: the module is ntoskrnl.exe
	dwType == 1: the module is win32k.sys

--*/
{
	ULONG	ulRet = 0;
	NTSTATUS	status;
	OBJECT_ATTRIBUTES	ObjAttr;
	HANDLE	hFile = NULL, hSection = NULL;
	IO_STATUS_BLOCK IoStatus;
	PUCHAR	pImageBase = NULL;
	SIZE_T	size = 0;
	PIMAGE_DOS_HEADER	pImageDosHeader = NULL;
	PIMAGE_NT_HEADERS	pImageNtHeaders = NULL;
	PIMAGE_SECTION_HEADER	pImageSectionHeader = NULL;
	ULONG i = 0;
	PUCHAR pEntryPoint = NULL;
	PUCHAR	pKeSerDesTable = NULL;
	PIMAGE_BASE_RELOCATION	pImageBaseRelocation = NULL;
	PIMAGE_FIXUP_ENTRY	pImageFixupEntry = NULL;
	ULONG	ulArryNum = 0;
	PULONG	pulItemToReloc = NULL;
	
	InitializeObjectAttributes(&ObjAttr, punModuleName, OBJ_CASE_INSENSITIVE,
								NULL, NULL);
	status = ZwCreateFile(&hFile, GENERIC_READ, &ObjAttr, &IoStatus, NULL, 0, FILE_SHARE_READ,
							FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
	if(status != STATUS_SUCCESS)
	{
		return ulRet;
	}

	ObjAttr.ObjectName = NULL;
	status = ZwCreateSection(&hSection, SECTION_MAP_EXECUTE, &ObjAttr, 0, PAGE_EXECUTE,
								0x1000000/*SEC_IMAGE*/, hFile);
	if(status != STATUS_SUCCESS)
	{
		ZwClose(hFile);
		return ulRet;
	}

	ZwMapViewOfSection(hSection, ZwCurrentProcess(), &pImageBase, 0, 0x400, 0, &size, ViewShare, 
							MEM_TOP_DOWN, PAGE_READWRITE);
	ZwClose(hFile);

	pImageDosHeader = (PIMAGE_DOS_HEADER)pImageBase;
	pImageNtHeaders = (PIMAGE_NT_HEADERS)(pImageBase + pImageDosHeader->e_lfanew);

	if(dwType == 1)
	{
		// funcs in win32k.sys
		if(g_pWin32kTable == NULL)
		{
			//pImageSectionHeader = (PIMAGE_SECTION_HEADER)((PUCHAR)&pImageNtHeaders->OptionalHeader + 
			//						*(PULONG)&pImageNtHeaders->FileHeader.SizeOfOptionalHeader);
			pImageSectionHeader = (PIMAGE_SECTION_HEADER)((PUCHAR)&pImageNtHeaders->OptionalHeader + pImageNtHeaders->FileHeader.SizeOfOptionalHeader);
			// for most os versions,
			// the func address of NtGdiXXX and NtUserXXX is in the .data section
			g_pWin32kTable = (PVOID)pImageSectionHeader[2].VirtualAddress;
			if(g_ulMajorVer == 5 && g_ulMajorVer == 0)
			{
				// for win2000, locate the func address by searching feature codes
				// search from the entry point of win32k.sys
				pEntryPoint = pImageBase + pImageNtHeaders->OptionalHeader.AddressOfEntryPoint;
				for(i = 0; i < 0x300; i++)
				{
					if(*(PULONG)pEntryPoint == 0x68 && *(PUSHORT)(pEntryPoint + 5) == 0x15FF)	// [Warning:]
					{
						g_pWin32kTable = (PVOID)(*(PULONG)(pEntryPoint + 1) - pImageNtHeaders->OptionalHeader.ImageBase);
						break;
					}
					pEntryPoint++;
				}
			}
		}
		
		if(g_pWin32kTable != NULL)
		{
			ulRet = *(PULONG)(pImageBase + (ULONG)g_pWin32kTable + 4 * dwFuncIndex) - 
						pImageNtHeaders->OptionalHeader.ImageBase;
		}
		else
		{
			KdPrint(("Get Shadow ServiceTable Failed!\n"));
		}
	}
	else
	{
		// funcs in ntoskrnl.exe
		if(g_pNtoskrnlTable == NULL)
		{
			pKeSerDesTable = GetProcAddressKernelMode(pImageBase, "KeServiceDescriptorTable");
			if(pKeSerDesTable != NULL)
			{
				pKeSerDesTable = pKeSerDesTable - (ULONG_PTR)pImageBase;

				// locate the func address by xref of relocation table
				pImageBaseRelocation = (PIMAGE_BASE_RELOCATION)(pImageBase + 
								pImageNtHeaders->OptionalHeader.DataDirectory[5].VirtualAddress);
				for(pImageBaseRelocation; pImageBaseRelocation != NULL && pImageBaseRelocation->SizeOfBlock != 0; 
					pImageBaseRelocation = (PIMAGE_BASE_RELOCATION)((PUCHAR)pImageBaseRelocation +
												pImageBaseRelocation->SizeOfBlock))
				{
					pImageFixupEntry = (PIMAGE_FIXUP_ENTRY)((PUCHAR)pImageBaseRelocation + sizeof(IMAGE_BASE_RELOCATION));
					ulArryNum = (pImageBaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION))/2;
					for(i = 0; i < ulArryNum; i++)
					{
						if(pImageFixupEntry[i].type == IMAGE_REL_BASED_HIGHLOW) // [Warning:]
						{
							pulItemToReloc = (PULONG)(pImageBase + pImageBaseRelocation->VirtualAddress + 
												pImageFixupEntry[i].offset);
							if(*pulItemToReloc == (ULONG_PTR)pKeSerDesTable + pImageNtHeaders->OptionalHeader.ImageBase)
							{
								if(*(PUSHORT)((PUCHAR)pulItemToReloc - 2) == 0x05c7)	// [Warning:]
								{
									g_pNtoskrnlTable = (PVOID)(*(pulItemToReloc + 1) - pImageNtHeaders->OptionalHeader.ImageBase);
									goto done;
								}
							}
						}
					}
				}
			}
		}

done:
		if(g_pNtoskrnlTable != NULL)
		{
			ulRet = *(PULONG)(pImageBase + (ULONG)g_pNtoskrnlTable + 4 * dwFuncIndex) - 
				pImageNtHeaders->OptionalHeader.ImageBase;
		}
		else
		{
			KdPrint(("Get KiServiceTable Failed!\n"));
		}
	}


	if(hSection != NULL)
	{
		ZwClose(hSection);
		hSection = NULL;
	}
	ZwUnmapViewOfSection(ZwCurrentProcess(), pImageBase);
	
	return ulRet;
}

PVOID GetOrigFunctionAddr(DWORD dwFuncIndex, DWORD dwType)
/*++

Routine Description:

	Get the function original addr by analyzing the corresponding file on the disk

	dwType == 0: the func is in ntoskrnl.exe
	dwType == 1: the func is in win32k.sys

--*/
{
	NTSTATUS	status;
	PSYSTEM_MODULE_INFORMATION	pSmi = NULL;
	ULONG	i = 0;
	char * pName = NULL;
	char szName[64] = {0};
	UNICODE_STRING unModuleName;
	ANSI_STRING	anModuleName;
	UNICODE_STRING unTarget;
	wchar_t szTarget[64];
	PVOID	pModuleBase = NULL;
	PVOID	pRet = NULL;

	if(dwType == 1)	// [Warning:]
	{
		pSmi = (PSYSTEM_MODULE_INFORMATION)GetSystemInformation(SystemModuleInformation);
		if(pSmi == NULL)
		{
			return NULL;
		}

		for(i = 0; i < pSmi->ModulesCount; i++)
		{
			pName = strrchr(pSmi->Modules[i].Name, '\\');
			if(pName != NULL)
			{
				pName++;
			}
			else
			{
				pName = pSmi->Modules[i].Name;
			}

			if(_stricmp(pName, "win32k.sys") == 0)
			{
				strcpy(szName, pName);
				g_Win32kBase = pSmi->Modules[i].ImageBaseAddress;
				g_ulWin32kSize = pSmi->Modules[i].ImageSize;
				pModuleBase = g_Win32kBase;
				break;
			}
		}

		if(pSmi != NULL)
		{
			ExFreePoolWithTag(pSmi, TAG_STRONG_OD);
		}
	}
	else
	{
		status = GetNtoskrnlInfo(szName, &g_ulNtoskrnlSize, &g_NtoskrnlBase);	
		if(!NT_SUCCESS(status))
		{
			return NULL;
		}
		pModuleBase = g_NtoskrnlBase;
	}

	unTarget.Buffer = szTarget;
	unTarget.Length = 0;
	unTarget.MaximumLength = sizeof(szTarget);

	RtlInitAnsiString(&anModuleName, szName);
	RtlAnsiStringToUnicodeString(&unModuleName, &anModuleName, TRUE);
	status = RtlAppendUnicodeToString(&unTarget, L"\\SystemRoot\\system32\\");
	if(NT_SUCCESS(status))
	{
		status = RtlAppendUnicodeStringToString(&unTarget, &unModuleName);
		RtlFreeUnicodeString(&unModuleName);	// [Warning:]
		pRet = (PVOID)GetFuncOffsetInModule(&unTarget, dwType, dwFuncIndex);
		if(pRet != NULL)
		{
			pRet = (PVOID)((ULONG)pRet + (ULONG)pModuleBase);
		}
	}
	else
	{
		RtlFreeUnicodeString(&unModuleName);	// [Warning:]
	}

	return pRet;
}

VOID WriteProtectOff()
/*++

Routine Description:

	Modify cr0 register

--*/
{
	__asm
	{
		cli
		push eax
		mov eax, cr0
		and eax, not 10000h
		mov cr0, eax
		pop eax
	}
}

VOID WriteProtectOn()
/*++

Routine Description:

	Recovery cr0 register

--*/
{
	__asm
	{
		push eax
		mov eax, cr0
		or eax, 10000h
		mov cr0, eax
		pop eax
		sti
	}
}

ULONG ModifySSDT(DWORD dwAddrToWrite, DWORD dwFuncIndex)
/*++

Routine Description:

	Modify SSDT Table

--*/
{
	ULONG	ulRet = 0;

	if(MmIsAddressValid((PVOID)dwAddrToWrite))
	{
		if(KeServiceDescriptorTable->Limit > dwFuncIndex)
		{
			WriteProtectOff();
			ulRet = (ULONG)InterlockedExchange((PLONG)(&KeServiceDescriptorTable->Base[dwFuncIndex]), (LONG)dwAddrToWrite);
			WriteProtectOn();
		}
	}

	return ulRet;
}

ULONG ModifySSDTShadow(DWORD dwAddrToWrite, DWORD dwFuncIndex)
/*++

Routine Description:

	Modify SSDTShadow Table

--*/
{
	ULONG ulRet = 0;

	if(MmIsAddressValid((PVOID)dwAddrToWrite))
	{
		if(MmIsAddressValid(win32k.Base))
		{
			if(win32k.Limit > dwFuncIndex)
			{
				WriteProtectOff();
				ulRet = InterlockedExchange((PLONG)&win32k.Base[dwFuncIndex], dwAddrToWrite);
				WriteProtectOn();
			}
		}
	}

	return ulRet;
}

VOID HookSSDT()
/*++

Routine Description:

	Modify SSDT Table and SSDTShadow Table

--*/
{
	NTSTATUS	status;
	PEPROCESS	pEProcess = NULL;
	KAPC_STATE	ApcState;

	if(g_dwIsSSDTHooked == 0)
	{
		g_dwOldSetContextThreadAddr = (ULONG)KeServiceDescriptorTable->Base[g_dwSetContextThreadIndex];
		g_dwOldQuerySystemInformationAddr = (ULONG)KeServiceDescriptorTable->Base[g_dwQuerySystemInformationIndex];
		g_dwOldQueryObjectAddr = (ULONG)KeServiceDescriptorTable->Base[g_dwQueryObjectIndex];
		g_dwOldYieldExecutionAddr = (ULONG)KeServiceDescriptorTable->Base[g_dwYieldExecutionIndex];
		g_dwOldOpenProcessAddr = (ULONG)KeServiceDescriptorTable->Base[g_dwOpenProcessIndex];
		g_dwOldOpenThreadAddr = (ULONG)KeServiceDescriptorTable->Base[g_dwOpenThreadIndex];
		g_dwOldSetInformationThreadAddr = (ULONG)KeServiceDescriptorTable->Base[g_dwSetInformationThreadIndex];
		g_dwOldQueryInformationProcessAddr = (ULONG)KeServiceDescriptorTable->Base[g_dwQueryInformationProcessIndex];
		g_dwOldCloseAddr = (ULONG)KeServiceDescriptorTable->Base[g_dwCloseIndex];
		g_dwOldDuplicateObjectAddr = (ULONG)KeServiceDescriptorTable->Base[g_dwDuplicateObjectIndex];
		if(g_ulMajorVer >= 6)
		{
			g_dwOldCreateUserProcessAddr = (ULONG)KeServiceDescriptorTable->Base[g_dwCreateUserProcessIndex];
		}
		else
		{
			g_dwOldCreateProcessAddr = (ULONG)KeServiceDescriptorTable->Base[g_dwCreateProcessIndex];
			g_dwOldCreateProcessExAddr = (ULONG)KeServiceDescriptorTable->Base[g_dwCreateProcessExIndex];	// [Warning:]
		}

		ModifySSDT((DWORD)pfMyQuerySystemInformation, g_dwQuerySystemInformationIndex);
		ModifySSDT((DWORD)pfMyQueryObject, g_dwQueryObjectIndex);
		ModifySSDT((DWORD)pfMyYieldExecution, g_dwYieldExecutionIndex);
		ModifySSDT((DWORD)pfMyOpenProcess, g_dwOpenProcessIndex);
		ModifySSDT((DWORD)pfMyOpenThread, g_dwOpenThreadIndex);
		ModifySSDT((DWORD)pfMySetInformationThread, g_dwSetInformationThreadIndex);
		ModifySSDT((DWORD)pfMyQueryInformationProcess, g_dwQueryInformationProcessIndex);
		ModifySSDT((DWORD)pfMyClose, g_dwCloseIndex);
		ModifySSDT((DWORD)pfMyDuplicateObject, g_dwDuplicateObjectIndex);
		
		if ( g_ulMajorVer >= 6 )
		{
			ModifySSDT((DWORD)pfMyCreateUserProcess, g_dwCreateUserProcessIndex);
		}
		else
		{
			ModifySSDT((DWORD)pfMyCreateProcess, g_dwCreateProcessIndex);
			ModifySSDT((DWORD)pfMyCreateProcessEx, g_dwCreateProcessExIndex);
		}

		if(g_dwCsrssProcId != 0)
		{
			status = PsLookupProcessByProcessId((HANDLE)g_dwCsrssProcId, &pEProcess);
			if(NT_SUCCESS(status))
			{
				KeStackAttachProcess(pEProcess, &ApcState);
				g_dwOldUserQueryWindowAddr = (ULONG)win32k.Base[g_dwUserQueryWindowIndex];
				g_dwOldUserFindWindowExAddr = (ULONG)win32k.Base[g_dwUserFindWindowExIndex];
				g_dwOldUserGetForegroundWindowAddr = (ULONG)win32k.Base[g_dwUserGetForegroundWindowIndex];
				g_dwOldUserSetParentAddr = (ULONG)win32k.Base[g_dwUserSetParentIndex];
				g_dwOldUserPostMessageAddr = (ULONG)win32k.Base[g_dwUserPostMessageIndex];
				if(g_ulMajorVer == 6 && g_ulMinorVer == 2 && g_ulBuildNum >= 0x23F0)
				{
					g_dwOldUserBuildHwndListWin8Addr = (ULONG)win32k.Base[g_dwUserBuildHwndListWin8Index];
					ModifySSDTShadow((ULONG)pfMyUserBuildHwndListWin8, g_dwUserBuildHwndListWin8Index);
				}
				else
				{
					g_dwOldUserBuildHwndListAddr = (ULONG)win32k.Base[g_dwUserBuildHwndListIndex];
					ModifySSDTShadow((ULONG)pfMyUserBuildHwndList, g_dwUserBuildHwndListIndex);
				}

				ModifySSDTShadow((ULONG)pfMyUserQueryWindow, g_dwUserQueryWindowIndex);
				ModifySSDTShadow((ULONG)pfMyUserFindWindowEx, g_dwUserFindWindowExIndex);
				ModifySSDTShadow((ULONG)pfMyUserGetForegroundWindow, g_dwUserGetForegroundWindowIndex);
				ModifySSDTShadow((ULONG)pfMyUserSetParent, g_dwUserSetParentIndex);
				ModifySSDTShadow((ULONG)pfMyUserPostMessage, g_dwUserPostMessageIndex);
				KeUnstackDetachProcess(&ApcState);
				ObDereferenceObject(pEProcess);
			}
		}
		g_dwIsSSDTHooked = 1;
	}
}

VOID UnhookSSDT()
/*++

Routine Description:

	Recovery SSDT Table and SSDTShadow Table

--*/
{
	NTSTATUS	status;
	PEPROCESS	pEProcess = NULL;
	KAPC_STATE	ApcState;

	if(g_dwIsSSDTHooked)
	{
		KdPrint(("Unhook!"));
		if(!MmIsAddressValid((PVOID)g_dwOldSetContextThreadAddr))
		{
			g_dwOldSetContextThreadAddr = (ULONG)pfOrigSetContextThread;
		}
		if(!MmIsAddressValid((PVOID)g_dwOldQuerySystemInformationAddr))
		{
			g_dwOldQuerySystemInformationAddr = (ULONG)pfOrigQuerySystemInformation;
		}
		if(!MmIsAddressValid((PVOID)g_dwOldQueryObjectAddr))
		{
			g_dwOldQueryObjectAddr = (ULONG)pfOrigQueryObject;
		}
		if(!MmIsAddressValid((PVOID)g_dwOldYieldExecutionAddr))
		{
			g_dwOldYieldExecutionAddr = (ULONG)pfOrigYieldExecution;
		}
		if(!MmIsAddressValid((PVOID)g_dwOldOpenProcessAddr))
		{
			g_dwOldOpenProcessAddr = (ULONG)pfOrigOpenProcess;
		}
		if(!MmIsAddressValid((PVOID)g_dwOldOpenThreadAddr))
		{
			g_dwOldOpenThreadAddr = (ULONG)pfOrigOpenThread;
		}
		if(!MmIsAddressValid((PVOID)g_dwOldSetInformationThreadAddr))
		{
			g_dwOldSetInformationThreadAddr = (ULONG)pfOrigSetInformationThread;
		}
		if(!MmIsAddressValid((PVOID)g_dwOldQueryInformationProcessAddr))
		{
			g_dwOldQueryInformationProcessAddr = (ULONG)pfOrigQueryInformationProcess;
		}
		if(!MmIsAddressValid((PVOID)g_dwOldCloseAddr))
		{
			g_dwOldCloseAddr = (ULONG)pfOrigClose;
		}
		if(!MmIsAddressValid((PVOID)g_dwOldDuplicateObjectAddr))
		{
			g_dwOldDuplicateObjectAddr = (ULONG)pfOrigDuplicateObject;
		}

		if(g_ulMajorVer >= 6)
		{
			if(!MmIsAddressValid((PVOID)g_dwOldCreateUserProcessAddr))
			{
				g_dwOldCreateUserProcessAddr = (ULONG)pfOrigCreateUserProcess;
			}
		}
		else
		{
			if(!MmIsAddressValid((PVOID)g_dwOldCreateProcessAddr))
			{
				g_dwOldCreateProcessAddr = (ULONG)pfOrigCreateProcess;
			}
			if(!MmIsAddressValid((PVOID)g_dwOldCreateProcessExAddr))
			{
				g_dwOldCreateProcessExAddr = (ULONG)pfOrigCreateProcessEx;
			}
		}

		//ModifySSDT(g_dwOldSetContextThreadAddr, g_dwSetContextThreadIndex);	// [Warning:no hook, so no recovery]
		ModifySSDT(g_dwOldQuerySystemInformationAddr, g_dwQuerySystemInformationIndex);
		ModifySSDT(g_dwOldQueryObjectAddr, g_dwQueryObjectIndex);
		ModifySSDT(g_dwOldYieldExecutionAddr, g_dwYieldExecutionIndex);
		ModifySSDT(g_dwOldOpenProcessAddr, g_dwOpenProcessIndex);
		ModifySSDT(g_dwOldOpenThreadAddr, g_dwOpenThreadIndex);
		ModifySSDT(g_dwOldSetInformationThreadAddr, g_dwSetInformationThreadIndex);
		ModifySSDT(g_dwOldQueryInformationProcessAddr, g_dwQueryInformationProcessIndex);
		ModifySSDT(g_dwOldCloseAddr, g_dwCloseIndex);
		ModifySSDT(g_dwOldDuplicateObjectAddr, g_dwDuplicateObjectIndex);
		
		if(g_ulMajorVer >= 6)
		{
			ModifySSDT(g_dwOldCreateUserProcessAddr, g_dwCreateUserProcessIndex);
		}
		else
		{
			ModifySSDT(g_dwOldCreateProcessAddr, g_dwCreateProcessIndex);
			ModifySSDT(g_dwOldCreateProcessExAddr, g_dwCreateProcessExIndex);
		}

		if(g_dwCsrssProcId != 0)
		{
			status = PsLookupProcessByProcessId((HANDLE)g_dwCsrssProcId, &pEProcess);
			if(NT_SUCCESS(status))
			{
				KeStackAttachProcess(pEProcess, &ApcState);
				if ( !MmIsAddressValid((PVOID)g_dwOldUserQueryWindowAddr) )
				{
					g_dwOldUserQueryWindowAddr = (DWORD)pfOrigUserQueryWindow;
				}
				if ( !MmIsAddressValid((PVOID)g_dwOldUserFindWindowExAddr) )
				{
					g_dwOldUserFindWindowExAddr = (DWORD)pfOrigUserFindWindowEx;
				}
				if ( !MmIsAddressValid((PVOID)g_dwOldUserGetForegroundWindowAddr) )
				{
					g_dwOldUserGetForegroundWindowAddr = (DWORD)pfOrigUserGetForegroundWindow;
				}
				if ( !MmIsAddressValid((PVOID)g_dwOldUserSetParentAddr) )
				{
					g_dwOldUserSetParentAddr = (DWORD)pfOrigUserSetParent;
				}
				if ( !MmIsAddressValid((PVOID)g_dwOldUserPostMessageAddr) )
				{
					g_dwOldUserPostMessageAddr = (DWORD)pfOrigUserPostMessage;
				}
				if ( g_ulMajorVer == 6 && g_ulMinorVer == 2 && g_ulBuildNum >= 0x23F0 )
				{
					if ( !MmIsAddressValid((PVOID)g_dwOldUserBuildHwndListWin8Addr) )
					{
						g_dwOldUserBuildHwndListWin8Addr = (DWORD)pfOrigUserBuildHwndListWin8;
					}
					ModifySSDTShadow(g_dwOldUserBuildHwndListWin8Addr, g_dwUserBuildHwndListWin8Index);
				}
				else
				{
					if ( !MmIsAddressValid((PVOID)g_dwOldUserBuildHwndListAddr) )
					{
						g_dwOldUserBuildHwndListAddr = (DWORD)pfOrigUserBuildHwndList;
					}
					ModifySSDTShadow(g_dwOldUserBuildHwndListAddr, g_dwUserBuildHwndListIndex);
				}

				ModifySSDTShadow(g_dwOldUserQueryWindowAddr, g_dwUserQueryWindowIndex);
				ModifySSDTShadow(g_dwOldUserFindWindowExAddr, g_dwUserFindWindowExIndex);
				ModifySSDTShadow(g_dwOldUserGetForegroundWindowAddr, g_dwUserGetForegroundWindowIndex);
				ModifySSDTShadow(g_dwOldUserSetParentAddr, g_dwUserSetParentIndex);
				ModifySSDTShadow(g_dwOldUserPostMessageAddr, g_dwUserPostMessageIndex);

				KeUnstackDetachProcess(&ApcState);
				ObDereferenceObject(pEProcess);
			}
		}
		g_dwIsSSDTHooked = 0;
	}

}

VOID ReadMsr(int RegisterAddr, LARGE_INTEGER * pliValue)
/*++

Routine Description:

	read the model-specific register

--*/
{
	int lo;
	int hi;

	__asm
	{
		mov ecx,RegisterAddr
		rdmsr
		mov lo, eax
		mov hi, edx

		mov eax, pliValue
		mov ecx, lo
		mov [eax], ecx

		mov edx, pliValue
		mov eax, hi
		mov [edx+4], eax
	}
}

VOID WriteMsr(int RegisterAddr, LARGE_INTEGER * pliValue)
/*++

Routine Description:

	write the model-specific register

--*/
{
	int lo;
	int hi;

	__asm
	{
		mov eax, pliValue
		mov ecx, [eax]
		mov lo, ecx

		mov edx, pliValue
		mov eax, [edx+4]
		mov hi, eax

		mov eax, lo
		mov edx, hi
		mov ecx, RegisterAddr
		wrmsr
	}
}

typedef struct _IDT_INFO 
{
	USHORT IDTLimit;
	USHORT LowIdtBase;
	USHORT HiIdtBase;
}IDT_INFO, *PIDT_INFO;

#pragma pack(1)
typedef struct _IDT_ENTRY
{
	USHORT	LowOffset;
	USHORT	Selector;
	UCHAR	unused_Io;
	UCHAR	unused_hi:5;
	UCHAR	Dpl:2;
	UCHAR	P:1;
	USHORT	HiOffset;
}IDT_ENTRY, *PIDT_ENTRY;
#pragma pack()

#define MAKELONG(a, b)      ((LONG)(((USHORT)(((ULONG_PTR)(a)) & 0xffff)) | ((ULONG)((USHORT)(((ULONG_PTR)(b)) & 0xffff))) << 16))

ULONG ModifyIdt(char IdtNum, char NewDpl, char * pOldDpl, ULONG NewIdtHandler)
/*++

Routine Description:

	modify the idt table

Parameters:

	IdtNum:			[in]the idt number
	NewDpl:			[in]the new descriptor privilege level that you want to set for the NewIdtHandler
	pOldDpl:		[out]the old descriptor privilege level
	NewIdtHandler:	[in]your idt handler

--*/
{
	IDT_INFO	IdtInfo;
	PIDT_ENTRY	pIdtEntry;

	ULONG	OldIdtHandler = 0;
	int i = 0;

	for(i = 0; i < KeNumberProcessors; i++)
	{
		KeSetAffinityThread(KeGetCurrentThread(), 1 << i);

		__asm sidt IdtInfo
		pIdtEntry = (PIDT_ENTRY)MAKELONG(IdtInfo.LowIdtBase, IdtInfo.HiIdtBase);

		// save old
		OldIdtHandler = (ULONG)MAKELONG(pIdtEntry[IdtNum].LowOffset, pIdtEntry[IdtNum].HiOffset);
		if(pOldDpl != NULL)
		{
			*pOldDpl = pIdtEntry[IdtNum].Dpl;
		}

		if(NewIdtHandler != 0)
		{
			__asm cli
			pIdtEntry[IdtNum].LowOffset = (USHORT)NewIdtHandler;
			pIdtEntry[IdtNum].HiOffset = (USHORT)((ULONG)NewIdtHandler >> 16);
			pIdtEntry[IdtNum].Dpl = (NewDpl & 3);
			__asm sti
		}
	}

	return OldIdtHandler;
}

VOID HookTrap01()
/*++

Routine Description:

	replace the handler of INT1(KiTrap01)

--*/
{
	g_ulOldTrap01 = ModifyIdt(1, 0, &g_OldDpl, (ULONG)MyTrap01);
	KdPrint(("Hook trap01, old addr:%X\n", g_ulOldTrap01));
}

VOID UnhookTrap01()
/*++

Routine Description:

	recovery the handler of INT1(KiTrap01)

--*/
{
	ModifyIdt(1, g_OldDpl, &g_OldDpl, g_ulOldTrap01);
	KdPrint(("UnHook trap01\n"));
}

VOID HookINT1()
/*++

Routine Description:

	Hook INT1 and modify msr register to enable BTF&LBR

--*/
{
	int i = 0;

	if(g_IsINT1Hooked != 1 && g_IsEnableLBR && g_IsSupportLBR)
	{
		HookTrap01();
		for(i = 0; i < KeNumberProcessors; i++)
		{
			KeSetAffinityThread(KeGetCurrentThread(), 1 << i);

			// enable btf and lbr
			ReadMsr(0x1d9, &g_liDbgCtrlRegValue);
			g_liDbgCtrlRegValue.LowPart |= 3;
			WriteMsr(0x1d9, &g_liDbgCtrlRegValue);
		}

		g_IsINT1Hooked = 1;
	}
}

VOID UnhookINT1()
/*++

Routine Description:

	Unhook INT1 and recovery the debug control register to 
	disable BTF&LBR

--*/
{
	int i = 0;

	if(g_IsINT1Hooked && g_IsEnableLBR && g_IsSupportLBR)
	{
		for(i = 0; i < KeNumberProcessors; i++)
		{
			KeSetAffinityThread(KeGetCurrentThread(), 1 << i);

			// recovery the debug ctrl register
			ReadMsr(0x1d9, &g_liDbgCtrlRegValue);
			g_liDbgCtrlRegValue.LowPart &= 0xFFFFFFFC;
			WriteMsr(0x1d9, &g_liDbgCtrlRegValue);
		}

		UnhookTrap01();
		g_IsINT1Hooked = 0;
	}
}

UCHAR Key[0x100] = 
{
	0x42, 0xA3, 0x53, 0x4,  0x4D, 0x4B, 0xA3, 0xC4, 0xEC, 0xF8,
	0xE5, 0x41, 0x9D, 0xEF, 0xAE, 0x46, 0x95, 0x59, 0x7D, 0xF3,
	0x98, 0xBD, 0xDC, 0xD4, 0x1F, 0xE9, 0xC1, 0xD9, 0xFB, 0xF1, 
	0xE9, 0x8D, 0x85, 0xB,  0x7B, 0x14, 0x56, 0x12, 0x33, 0xCC, 
	0xFD, 0x47, 0x48, 0xF5, 0xC,  0x4C, 0x24, 0xC2, 0x3D, 0x2F, 
	0xB6, 0xC4, 0x66, 0xD3, 0xDD, 0x73, 0x54, 0xAE, 0xE4, 0x4F, 
	0xF1, 0x1B, 0x94, 0xFC, 0xBC, 0x4E, 0x7C, 0x66, 0xF4, 0x90, 
	0xCD, 0xA1, 0xA2, 0xF7, 0xB6, 0xDD, 0x83, 0x57, 0x4,  0x7C, 
	0x10, 0x14, 0x20, 0x10, 0xF4, 0x3C, 0x2C, 0x7A, 0x87, 0x30, 
	0xAB, 0x3C, 0xDE, 0x86, 0x31, 0xCE, 0x4D, 0x63, 0xAD, 0xCB,
	0xB3, 0x13, 0x94, 0xFA, 0x5B, 0xD5, 0x88, 0x98, 0x6,  0x29,
	0xEB, 0xA0, 0x20, 0x3A, 0xDB, 0x7A, 0x80, 0xBD, 0x1D, 0x8,
	0xC3, 0x5,  0x56, 0xCA, 0x44, 0xA1, 0xAB, 0x3A, 0x41, 0x43,
	0x6A, 0x2C, 0x64, 0x27, 0x53, 0xCD, 0xE9, 0x9,  0x45, 0x16,
	0x46, 0xAF, 0xBE, 0xB8, 0xD,  0x8D, 0xBA, 0x1B, 0xE1, 0xF3,
	0xD2, 0x50, 0xAA, 0xD1, 0x3C, 0xCA, 0xEA, 0x8D, 0x10, 0xE5,
	0x59, 0x2C, 0xA1, 0x21, 0x9B, 0x8,  0xDB, 0x2E, 0x2C, 0x62,
	0x6E, 0xFF, 0xB1, 0xEB, 0xAA, 0x2D, 0x90, 0xFF, 0xC,  0x59,
	0x7B, 0x3A, 0x8,  0xEC, 0xA,  0xC9, 0xC3, 0x4C, 0x63, 0x4F,
	0x73, 0xC1, 0xC8, 0x4E, 0xA5, 0x9C, 0xB0, 0xEE, 0xF4, 0xEE,
	0x4D, 0x93, 0x13, 0x67, 0x9E, 0x3D, 0x4D, 0xA6, 0x1,  0x5F,
	0x1F, 0x61, 0x8F, 0x9E, 0x57, 0xAC, 0x44, 0xB5, 0xFB, 0x40,
	0x1E, 0xFC, 0x0,  0xAE, 0xDA, 0x36, 0xEA, 0x49, 0x64, 0x5,
	0x1A, 0x1B, 0x4E, 0xD4, 0x29, 0x4D, 0xBB, 0x81, 0x7D, 0x6B,
	0xC4, 0xF2, 0x39, 0x98, 0xC9, 0x2F, 0xB7, 0xCB, 0xBD, 0x6D,
	0xFC, 0x3E, 0xC9, 0x3E, 0x20, 0xAB
};

VOID EncAndDecBuffer(PVOID pBuffer, ULONG ulLen)
/*++

Routine Description:

	Encrypt and Decrypt the communicate buffer that be used 
	in IRP_MJ_DEVICE_CONTROL handler

--*/
{
	ULONG i = 0;
	for(i = 0; i < ulLen; i++)
	{
		*((PUCHAR)pBuffer + i%0x100) ^= Key[i%0x100];
	}
}