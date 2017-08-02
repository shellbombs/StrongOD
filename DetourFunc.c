/*++

Copyright (c) Bombs

Module Name:
	
	DetourFunc.c

Author  :Bombs
Time    :2014-5-8 20:00:47
Abstract:
   
	This module implements our functions that used for replacing 
	system functions(as is well-known hooks)

--*/

#include <ntifs.h>
#include "DetourFunc.h"
#include "HelperFunc.h"
#include "CommDef.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, MySetInformationThread)
#pragma alloc_text(PAGE, MyClose)
#pragma alloc_text(PAGE, MyDuplicateObject)
#pragma alloc_text(PAGE, MyQueryObject)
#pragma alloc_text(PAGE, MyQuerySystemInformation)
#pragma alloc_text(PAGE, MyYieldExecution)
#pragma alloc_text(PAGE, MyOpenProcess)
#pragma alloc_text(PAGE, MyOpenThread)
#pragma alloc_text(PAGE, MySetContextThread)
#pragma alloc_text(PAGE, MyQueryInformationProcess)
#endif

//
// Global variable
//

PLIST_NODE	g_pProcInfo = NULL;
ULONG	g_ulDr6 = 0;
LARGE_INTEGER g_liReg1DBValue = {0};
PLARGE_INTEGER g_pliReg1DB = &g_liReg1DBValue;
LARGE_INTEGER g_liReg1DCValue = {0};
PLARGE_INTEGER g_pliReg1DC = &g_liReg1DCValue;
ULONG	g_ulIsJustRet = 0;

BOOLEAN MyUserPostMessage(ULONG hWnd, ULONG Msg, ULONG wParam, ULONG lParam)
/*++

Routine Description:

	Disable BROADCAST Message

--*/
{
	BOOLEAN	bRet = TRUE;

	if( hWnd != 0xFFFF /*HWND_BROADCAST*/)
	{
		bRet = pfOrigUserPostMessage(hWnd, Msg, wParam, lParam);
	}

	return bRet;
}

NTSTATUS __stdcall MySetInformationThread(HANDLE ThreadHandle,
										  ULONG ThreadInformationClass,
										  PVOID ThreadInformation,
										  ULONG ThreadInformationLength)
/*++

Routine Description:

	check if ThreadInformationClass equals ThreadHideFromDebugger, if it is, 
	just return.

--*/
{
	NTSTATUS status;
	PVOID	Object;

	status = ObReferenceObjectByHandle(ThreadHandle, GENERIC_READ, 0, KernelMode, &Object, NULL);
	if(NT_SUCCESS(status))
	{
		ObDereferenceObject(Object);		
	}

	if(ThreadInformationClass != ThreadHideFromDebugger)
	{
		status = pfOrigSetInformationThread(ThreadHandle, ThreadInformationClass,
						ThreadInformation, ThreadInformationLength);
	}

	return status;
}

NTSTATUS __stdcall MyUserBuildHwndList(
									   HANDLE hDesktop,
									   HANDLE hWndParent,
									   ULONG bEnumChildren,
									   ULONG dwThreadId,
									   ULONG lParam,
									   HANDLE * pWnd,
									   ULONG * pBufSize)
/*++

Routine Description:

	Get rid of the OD hwnds from the pWnd list

--*/
{
	NTSTATUS status = STATUS_SUCCESS;
	BOOLEAN	bPass = TRUE;
	ULONG	ulProcId;
	PEPROCESS	pEProcess = NULL;
	ULONG i = 0, j = 0;

	do 
	{
		if(g_dwIsHidenWindow == FALSE || IsProcessInList(IoGetCurrentProcess(), 0, SOD_WHITE_PROCESS))
		{
			break;
		}

		if(bEnumChildren == 1)
		{
			ulProcId = pfOrigUserQueryWindow(hWndParent, 0);
			if(NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)ulProcId, &pEProcess)))
			{
				if(IsProcessInList(pEProcess, 0, SOD_WHITE_PROCESS))
				{
					bPass = FALSE;
				}
				ObDereferenceObject(pEProcess);
			}
		}

		if(bPass == FALSE)
		{
			break;
		}

		status = pfOrigUserBuildHwndList(hDesktop, hWndParent, bEnumChildren, 
					dwThreadId, lParam, pWnd, pBufSize);

		bPass = FALSE;

		if(!NT_SUCCESS(status))
		{
			break;
		}

		while(i < *pBufSize)
		{
			ulProcId = pfOrigUserQueryWindow(pWnd[i], 0);
			if(NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)ulProcId, &pEProcess)))
			{
				if(IsProcessInList(pEProcess, 0, SOD_WHITE_PROCESS))
				{
					ObDereferenceObject(pEProcess);
					i++;
					continue;
				}
				ObDereferenceObject(pEProcess);
			}
			// find a hwnd which doesn't belong to OD to replace the OD hwnd
			pWnd[j++] = pWnd[i];
			i++;
		}

		for (i = j; i < *pBufSize; i++)
		{
			pWnd[i] = 0;
		}
		*pBufSize = j;

	} while (0);

	if(bPass)
	{
		status = pfOrigUserBuildHwndList(hDesktop, hWndParent, bEnumChildren, dwThreadId, lParam,
						pWnd, pBufSize);
	}

	return status;
}

NTSTATUS __stdcall MyUserBuildHwndListWin8(
	ULONG a1,
	HANDLE a2,
	ULONG bEnumChildren,
	ULONG a4,
	ULONG a5,
	ULONG a6,
	HANDLE * pWnd,
	ULONG * pBufSize)
/*++

Routine Description:

	a function available on win8, like MyUserBuildHwndList

--*/
{
	NTSTATUS status = STATUS_SUCCESS;
	BOOLEAN	bPass = TRUE;
	ULONG	ulProcId;
	PEPROCESS	pEProcess = NULL;
	ULONG i = 0, j = 0;

	do 
	{
		if(g_dwIsHidenWindow == FALSE || IsProcessInList(IoGetCurrentProcess(), 0, SOD_WHITE_PROCESS))
		{
			break;
		}

		if(bEnumChildren == 1)
		{
			ulProcId = pfOrigUserQueryWindow(a2, 0);
			if(NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)ulProcId, &pEProcess)))
			{
				if(IsProcessInList(pEProcess, 0, SOD_WHITE_PROCESS))
				{
					bPass = FALSE;
				}
				ObDereferenceObject(pEProcess);
			}
		}

		if(bPass == FALSE)
		{
			break;
		}

		status = pfOrigUserBuildHwndListWin8(a1, a2, bEnumChildren, 
			a4, a5, a6, pWnd, pBufSize);

		bPass = FALSE;

		if(!NT_SUCCESS(status))
		{
			break;
		}

		while(i < *pBufSize)
		{
			ulProcId = pfOrigUserQueryWindow(pWnd[i], 0);
			if(NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)ulProcId, &pEProcess)))
			{
				if(IsProcessInList(pEProcess, 0, SOD_WHITE_PROCESS))
				{
					ObDereferenceObject(pEProcess);
					i++;
					continue;
				}
				ObDereferenceObject(pEProcess);
			}
			// find a hwnd which doesn't belong to OD to replace the OD hwnd
			pWnd[j++] = pWnd[i];
			i++;
		}

		for (i = j; i < *pBufSize; i++)
		{
			pWnd[i] = 0;
		}
		*pBufSize = j;

	} while (0);

	if(bPass)
	{
		status = pfOrigUserBuildHwndListWin8(a1, a2, bEnumChildren, a4, a5, a6,
			pWnd, pBufSize);
	}

	return status;
}

NTSTATUS CheckHandle(HANDLE Handle)
/*++

Routine Description:

	check if the handle is a valid handle

--*/
{
	NTSTATUS status;
	OBJECT_HANDLE_INFORMATION	HandleInfo = {0};
	PVOID Object;

	if(NT_SUCCESS( ObReferenceObjectByHandle(Handle, 0, NULL, KernelMode, &Object, &HandleInfo)))
	{
		if(HandleInfo.HandleAttributes & 1)
		{
			status = STATUS_HANDLE_NOT_CLOSABLE;
		}
		else
		{
			status = STATUS_SUCCESS;
		}
		ObDereferenceObject(Object);
	}
	else
	{
		status = STATUS_INVALID_HANDLE;
	}

	return status;
}

NTSTATUS __stdcall MyClose(
						   HANDLE Handle)
/*++

Routine Description:

	check if the Handle is valid or not, if it is,
	call original function, or return STATUS_INVALID_HANDLE

--*/
{
	NTSTATUS status;
	BOOLEAN	bIsHandleValid = TRUE;

	if(IsProcessInList(IoGetCurrentProcess(), 0, SOD_BLACK_PROCESS))
	{
		status = CheckHandle(Handle);
		if(!NT_SUCCESS(status))
		{
			bIsHandleValid = FALSE;
		}
	}

	if(bIsHandleValid)
	{
		status = pfOrigClose(Handle);
	}

	return status;
}

HANDLE __stdcall MyUserSetParent(
								 HANDLE hChild,
								 HANDLE hParent)
 /*++
 
 Routine Description:
 
 	if a process wants to set its hwnd as od's parent window or child window,
	disable it.
 
 --*/
{
	BOOLEAN	bPass = TRUE;
	ULONG ulProcId = 0;
	PEPROCESS pEProcess = NULL;
	HANDLE hParentPre = NULL;

	do 
	{
		if(!IsProcessInList(IoGetCurrentProcess(), 0, SOD_WHITE_PROCESS) &&
			g_dwIsHidenWindow == TRUE)
		{
			ulProcId = pfOrigUserQueryWindow(hChild, 0);
			if(NT_SUCCESS( PsLookupProcessByProcessId((HANDLE)ulProcId, &pEProcess) ))
			{
				if(IsProcessInList(pEProcess, 0, SOD_WHITE_PROCESS))
				{
					// a process wants to set od's window as its child window
					bPass = FALSE;
					ObDereferenceObject(pEProcess);
					break;
				}
				ObDereferenceObject(pEProcess);
			}

			ulProcId = pfOrigUserQueryWindow(hParent, 0);
			if(NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)ulProcId, &pEProcess)))
			{
				if(IsProcessInList(pEProcess, 0, SOD_WHITE_PROCESS))
				{
					// a process wants to set its hwnd as the child of od's hwnd
					bPass = FALSE;
				}
				ObDereferenceObject(pEProcess);
			}
		}

	} while (0);

	if(bPass)
	{
		hParentPre = pfOrigUserSetParent(hChild, hParent);
	}

	return hParentPre;
}

HANDLE __stdcall MyUserFindWindowEx(
									HANDLE hParent,
									HANDLE hChild,
									PUNICODE_STRING punClassName,
									PUNICODE_STRING punWindowName,
									ULONG dwType)
/*++

Routine Description:

	if a non-white process wants to find a window which belongs to a white process
	then disable it.

--*/
{
	PEPROCESS pEProcess = NULL;
	HANDLE hRet = NULL;
	ULONG ulProcId = 0;

	hRet = pfOrigUserFindWindowEx(hParent, hChild, 
		punClassName, punWindowName, dwType);

	if(g_dwIsHidenWindow)
	{
		if(!IsProcessInList(IoGetCurrentProcess(), 0, SOD_WHITE_PROCESS))
		{
			ulProcId = pfOrigUserQueryWindow(hRet, 0);
			if(NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)ulProcId, &pEProcess)))
			{
				if(IsProcessInList(pEProcess, 0, SOD_WHITE_PROCESS))
				{
					hRet = NULL;
				}
				ObDereferenceObject(pEProcess);
			}
		}
	}

	return hRet;
}

NTSTATUS __stdcall MyDuplicateObject(
									 HANDLE SourceProcessHandle,
									 HANDLE SourceHandle,
									 HANDLE TargetProcessHandle,
									 PHANDLE TargetHandle,
									 ACCESS_MASK DesiredAccess,
									 ULONG HandleAttributes,
									 ULONG Options)
 /*++
 
 Routine Description:
 
 	check if the SourceHandle is valid or not, if it isn't, 
	just return.
 
 --*/
{
	PEPROCESS pEProcess = NULL;
	BOOLEAN	bIsHandleValid = TRUE;
	NTSTATUS status;

	if(IsProcessInList(IoGetCurrentProcess(), 0, SOD_BLACK_PROCESS))
	{
		if(Options & 1)
		{
			status = CheckHandle(SourceHandle);
			if(!NT_SUCCESS(status))
			{
				bIsHandleValid = FALSE;
			}
		}
	}

	if(bIsHandleValid)
	{
		status = pfOrigDuplicateObject(SourceProcessHandle, 
					SourceHandle, TargetProcessHandle, 
					TargetHandle, DesiredAccess, HandleAttributes, Options);
	}

	return status;
}

NTSTATUS __stdcall MyCreateUserProcess(
									   PHANDLE ProcessHandle,
									   PHANDLE ThreadHandle,
									   ACCESS_MASK ProcessDesiredAccess,
									   ACCESS_MASK ThreadDesiredAccess,
									   POBJECT_ATTRIBUTES ProcessObjectAttributes,
									   POBJECT_ATTRIBUTES ThreadObjectAttributes,
									   ULONG CreateProcessFlags,
									   ULONG CreateThreadFlags,
									   PVOID ProcessParameters,
									   PVOID Parameter9,
									   PVOID AttributeList)
/*++

Routine Description:

	Set parent process ProcessDebugFlags, 
	Here is for what? I don't know either.

--*/
{
	NTSTATUS status;
	PVOID ProcessInformation;
	ULONG_PTR	ulValue = 0;

	do 
	{
		if(!IsProcessInList(IoGetCurrentProcess(), 0, SOD_BLACK_PROCESS))
		{
			break;
		}

		if(!NT_SUCCESS(ZwQueryInformationProcess(ZwCurrentProcess(), 
						ProcessDebugFlags, &ProcessInformation,
						4, NULL)))
		{
			break;
		}

		if((ULONG)ProcessInformation != 1)
		{
			break;
		}

		ZwSetInformationProcess(ZwCurrentProcess(), ProcessDebugFlags, &ulValue, 4);
		status = pfOrigCreateUserProcess(ProcessHandle, ThreadHandle, 
			ProcessDesiredAccess, ThreadDesiredAccess, 
			ProcessObjectAttributes, ThreadObjectAttributes, 
			CreateProcessFlags, CreateThreadFlags, 
			ProcessParameters, Parameter9, AttributeList);
		ZwSetInformationProcess(ZwCurrentProcess(), ProcessDebugFlags, &ProcessInformation, 4);
		goto done;

	} while (0);

	status = pfOrigCreateUserProcess(ProcessHandle, ThreadHandle, 
						ProcessDesiredAccess, ThreadDesiredAccess, 
						ProcessObjectAttributes, ThreadObjectAttributes, 
						CreateProcessFlags, CreateThreadFlags, 
						ProcessParameters, Parameter9, AttributeList);

done:
	return status;
}

int GetDebugObjectNameAddr(char * pSearch, int size, wchar_t * name)
/*++

Routine Description:

	search string "DebugObject" from the buffer pointed by pSearch

--*/
{
	int i = 0;

	if(*name != L'\0')
	{
		for(i = 0; i < size; i++)
		{
			if(0 == wcscmp((wchar_t *)(pSearch + i), name))
			{
				return i;
			}
		}
	}

	return -1;
}

NTSTATUS __stdcall MyQueryObject(
								 HANDLE ObjectHandle,
								 ULONG ObjectInformationClass,
								 PVOID ObjectInformation,
								 ULONG Length,
								 PULONG ReturnLength)
 /*++
 
 Routine Description:
 
 	Hide DebugObject
 
 --*/
{
	NTSTATUS status;
	int nOffset = 0;

	status = pfOrigQueryObject(ObjectHandle, ObjectInformationClass, ObjectInformation,
					Length, ReturnLength);

	if(NT_SUCCESS(status))
	{
		if(IsProcessInList(IoGetCurrentProcess(), 0, SOD_BLACK_PROCESS)
			&& ObjectInformationClass == 3 /*ObjectAllTypeInformation*/)
		{
			nOffset = GetDebugObjectNameAddr((char *)ObjectInformation, Length - 22, L"DebugObject");
			if(nOffset != -1)
			{
				// locate DebugObject Number
				nOffset = nOffset - 88;
				*(PULONG)((char *)ObjectInformation + nOffset) = 0;	// TotalNumberofHandles
				*(PULONG)((char *)ObjectInformation + nOffset + 4) = 0;	// TotalNumberofObjects
			}
		}
	}

	return status;
}

NTSTATUS __stdcall MyQuerySystemInformation(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG Length,
	PULONG ReturnLength)
/*++

Routine Description:

	SystemKernelDebuggerInformation:Hide Kernel Debugger Info
	SystemProcessesAndThreadsInformation:Hide Process
	SystemHandleInformation:Hide Process
	SystemModuleInformation:Hide the driver

--*/
{
	NTSTATUS status;
	PSYSTEM_PROCANDTHREAD_INFORMATION pProcAndThreadInfo = NULL;
	PSYSTEM_PROCANDTHREAD_INFORMATION pProcAndThreadInfoNext = NULL;
	PEPROCESS pEProcess = NULL;
	PSYSTEM_HANDLE_INFORMATION	pSysHandleInfo = NULL;
	ULONG i = 0;
	PSYSTEM_MODULE_INFORMATION	pSysModuleInfo = NULL;
	BOOLEAN	bShouldClear = FALSE;
	KAPC_STATE	ApcState;
	PVOID Object;

	status = pfOrigQuerySystemInformation(SystemInformationClass, 
		SystemInformation, Length, ReturnLength);

	if(NT_SUCCESS(status) && !IsProcessInList(IoGetCurrentProcess(), 0, SOD_WHITE_PROCESS))
	{
		// a non-white process call NtQuerySystemInformation
		switch(SystemInformationClass)
		{
		case SystemKernelDebuggerInformation:
			{
				// hide kernel debugger
				RtlZeroMemory(SystemInformation, Length);
			}
			break;
		case SystemProcessesAndThreadsInformation:
			{
				// hide od
				pProcAndThreadInfo = (PSYSTEM_PROCANDTHREAD_INFORMATION)SystemInformation;
				if(g_dwIsHidenProcess)
				{
					while(pProcAndThreadInfo->NextEntryDelta != 0)
					{
						pProcAndThreadInfoNext = (PSYSTEM_PROCANDTHREAD_INFORMATION)((PUCHAR)pProcAndThreadInfo 
										+ pProcAndThreadInfo->NextEntryDelta);
						if(NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pProcAndThreadInfoNext->ProcessId,
							&pEProcess)))
						{
							if(IsProcessInList(pEProcess, 0, SOD_WHITE_PROCESS))
							{
								// clear white process info
								if(pProcAndThreadInfoNext->NextEntryDelta != 0)
								{
									pProcAndThreadInfo->NextEntryDelta += pProcAndThreadInfoNext->NextEntryDelta;
								}
								else
								{
									pProcAndThreadInfo->NextEntryDelta = 0;
								}
								RtlZeroMemory(pProcAndThreadInfoNext, pProcAndThreadInfoNext->NextEntryDelta);
							}
							else
							{
								pProcAndThreadInfo = pProcAndThreadInfoNext;
							}
							ObDereferenceObject(pEProcess);
						}
					}
				}

				if(g_ulMajorVer == 6)
				{
					// set parent process id to explorer
					for(pProcAndThreadInfo = (PSYSTEM_PROCANDTHREAD_INFORMATION)SystemInformation;
						pProcAndThreadInfo->NextEntryDelta != 0;
						pProcAndThreadInfo = (PSYSTEM_PROCANDTHREAD_INFORMATION)((PUCHAR)pProcAndThreadInfo + pProcAndThreadInfo->NextEntryDelta))
					{
						if(NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pProcAndThreadInfo->ProcessId, &pEProcess)))
						{
							if(IsProcessInList(pEProcess, 0, SOD_BLACK_PROCESS))
							{
								pProcAndThreadInfo->InheritedFromProcessId = g_dwExplorerProcId;
							}
							ObDereferenceObject(pEProcess);
						}
					}
				}
			}
			break;
		case SystemHandleInformation:
			{
				pSysHandleInfo = (PSYSTEM_HANDLE_INFORMATION)SystemInformation;
				if(g_dwIsProtectProcess || g_dwIsHidenProcess)
				{
					for(i = 0; i < pSysHandleInfo->NumberOfHandles; i++)
					{
						if(NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pSysHandleInfo->Handles[i].ProcessId, &pEProcess)))
						{
							if(*(PULONG)((PUCHAR)pEProcess + g_dwExitTimeOffsetInEProcess)
								|| IsProcessInList(pEProcess, 0, SOD_WHITE_PROCESS))
							{
								RtlZeroMemory(&pSysHandleInfo->Handles[i], 16);
								ObDereferenceObject(pEProcess);
							}
							else
							{
								if(pSysHandleInfo->Handles[i].ObjectTypeIndex == 5)
								{
									KeStackAttachProcess(pEProcess, &ApcState);
									if(NT_SUCCESS(ObReferenceObjectByHandle(
										(HANDLE)pSysHandleInfo->Handles[i].HandleValue,
										GENERIC_READ, NULL, KernelMode, &Object, NULL)))
									{
										if(IsProcessInList((PEPROCESS)Object, 0, SOD_WHITE_PROCESS))
										{
											bShouldClear = TRUE;
										}
										ObDereferenceObject(Object);
									}
									KeUnstackDetachProcess(&ApcState);
								}
								else if(pSysHandleInfo->Handles[i].ObjectTypeIndex == 6)
								{
									KeStackAttachProcess(pEProcess, &ApcState);
									if(NT_SUCCESS(ObReferenceObjectByHandle(
										(HANDLE)pSysHandleInfo->Handles[i].HandleValue,
										GENERIC_READ, NULL, KernelMode, &Object, NULL)))
									{
										if(IsProcessInList(IoThreadToProcess((PETHREAD)Object), 0, SOD_WHITE_PROCESS))
										{
											bShouldClear = TRUE;
										}
										ObDereferenceObject(Object);
									}
									KeUnstackDetachProcess(&ApcState);
								}

								if(bShouldClear)
								{
									RtlZeroMemory(&pSysHandleInfo->Handles[i], 16);
								}

								ObDereferenceObject(pEProcess);
							}
						}
					}
				}
			}
			break;
		case SystemModuleInformation:
			{
				pSysModuleInfo = (PSYSTEM_MODULE_INFORMATION)SystemInformation;

				for(i = 0; i < pSysModuleInfo->ModulesCount; i++)
				{
					if(pSysModuleInfo->Modules[i].ImageBaseAddress == g_pDriverStart
						&& pSysModuleInfo->Modules[i].ImageSize == g_ulDriverSize)
					{
						pSysModuleInfo->Modules[i].ImageSize = pSysModuleInfo->Modules[0].ImageSize;
					}
				}
			}
			break;
		default:
			break;
		}
	}

	return status;
}

NTSTATUS __stdcall MyYieldExecution(VOID)
/*++

Routine Description:

	return STATUS_NO_YIELD_PERFORMED to hide debugger

--*/
{
	NTSTATUS status = pfOrigYieldExecution();

	return STATUS_NO_YIELD_PERFORMED;
}

NTSTATUS __stdcall MyCreateProcess(
								   PHANDLE ProcessHandle,
								   ACCESS_MASK DesiredAccess,
								   POBJECT_ATTRIBUTES ObjectAttributes,
								   HANDLE ParentProcess,
								   BOOLEAN InheritObjectTable,
								   HANDLE SectionHandle,
								   HANDLE DebugPort,
								   HANDLE ExceptionPort)
/*++

Routine Description:

	See MyCreateUserProcess.

--*/
{
	NTSTATUS status;
	PVOID ProcessInformation;
	ULONG_PTR	ulValue = 0;

	do 
	{
		if(!IsProcessInList(IoGetCurrentProcess(), 0, SOD_BLACK_PROCESS))
		{
			break;
		}

		if(!NT_SUCCESS(ZwQueryInformationProcess(ZwCurrentProcess(), 
			ProcessDebugFlags, &ProcessInformation,
			4, NULL)))
		{
			break;
		}

		if((ULONG)ProcessInformation != 1)
		{
			break;
		}

		ZwSetInformationProcess(ZwCurrentProcess(), ProcessDebugFlags, &ulValue, 4);
		status = pfOrigCreateProcess(ProcessHandle, DesiredAccess,
							ObjectAttributes, ParentProcess, InheritObjectTable,
							SectionHandle, DebugPort, ExceptionPort);
		ZwSetInformationProcess(ZwCurrentProcess(), ProcessDebugFlags, &ProcessInformation, 4);
		goto done;

	} while (0);

	status = pfOrigCreateProcess(ProcessHandle, DesiredAccess,
			ObjectAttributes, ParentProcess, InheritObjectTable,
			SectionHandle, DebugPort, ExceptionPort);

done:
	return status;
}

NTSTATUS __stdcall MyOpenProcess(
								 PHANDLE ProcessHandle,
								 ACCESS_MASK DesiredAccess,
								 POBJECT_ATTRIBUTES ObjectAttributes,
								 PCLIENT_ID ClientId
								 )
 /*++
 
 Routine Description:
 
 	if a non-white process wants to open a white process, then refuse it
 
 --*/
{
	NTSTATUS	status;
	PEPROCESS	pEProcess = NULL;

	status = pfOrigOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
	if(NT_SUCCESS(status))
	{
		if(!IsProcessInList(IoGetCurrentProcess(), 0, SOD_WHITE_PROCESS))
		{
			if( (HANDLE)g_dwSmssProcId != PsGetCurrentProcessId())
			{
				if(NT_SUCCESS(PsLookupProcessByProcessId(ClientId->UniqueProcess, &pEProcess)))
				{
					if(IsProcessInList(pEProcess, 0, SOD_WHITE_PROCESS) && g_dwIsProtectProcess)
					{
						NtClose(*ProcessHandle);
						*ProcessHandle = NULL;

						if(g_dwIsHidenProcess)
						{
							status = STATUS_INVALID_PARAMETER;
						}
						else
						{
							status = STATUS_ACCESS_DENIED;
						}
					}
					ObDereferenceObject(pEProcess);
				}

				if(g_dwIsProtectProcess && g_dwCsrssProcId == (ULONG)ClientId->UniqueProcess)
				{
					NtClose(*ProcessHandle);
					*ProcessHandle = NULL;
					status = pfOrigOpenProcess(ProcessHandle, DesiredAccess & (~PROCESS_DUP_HANDLE),
						ObjectAttributes, ClientId);
				}
			}
		}
	}

	return status;
}

ULONG __stdcall MyUserQueryWindow(
								  HANDLE hWnd, ULONG Index)
/*++

Routine Description:

	if a non-white process query a window which belongs to a white process,
	then refuse it.

--*/
{
	PEPROCESS pEProcess = NULL;
	ULONG ulRet = 0;
	BOOLEAN bPass = TRUE;

	if(g_dwIsHidenWindow)
	{
		if(!IsProcessInList(IoGetCurrentProcess(), 0, SOD_WHITE_PROCESS))
		{
			if(NT_SUCCESS( PsLookupProcessByProcessId(
				(HANDLE)pfOrigUserQueryWindow(hWnd, 0), &pEProcess)))
			{
				if(IsProcessInList(pEProcess, 0, SOD_WHITE_PROCESS))
				{
					bPass = FALSE;
				}
				ObDereferenceObject(pEProcess);
			}
		}
	}

	if(bPass)
	{
		ulRet = pfOrigUserQueryWindow(hWnd, Index);
	}

	return ulRet;
}

NTSTATUS __stdcall MyOpenThread(
								PHANDLE ThreadHandle,
								ACCESS_MASK DesiredAccess,
								POBJECT_ATTRIBUTES ObjectAttributes,
								PCLIENT_ID ClientId)
/*++

Routine Description:

	See MyOpenProcess

--*/
{
	PEPROCESS	pEProcess = NULL;
	PETHREAD	pEThread = NULL;
	NTSTATUS	status;

	status = pfOrigOpenThread(ThreadHandle, DesiredAccess,
					ObjectAttributes, ClientId);

	if(NT_SUCCESS(status))
	{
		if(!IsProcessInList(IoGetCurrentProcess(), 0, SOD_WHITE_PROCESS))
		{
			if(g_dwSmssProcId != (ULONG)PsGetCurrentProcessId() &&
				(g_ulMajorVer != 6 || g_dwCsrssProcId != (ULONG)PsGetCurrentProcessId()))
			{
				if(NT_SUCCESS(PsLookupThreadByThreadId(ClientId->UniqueThread, &pEThread)))
				{
					pEProcess = IoThreadToProcess(pEThread);
					if(IsProcessInList(pEProcess, 0, SOD_WHITE_PROCESS) 
						&& g_dwIsProtectProcess)
					{
						NtClose(*ThreadHandle);
						*ThreadHandle = NULL;
						if(g_dwIsHidenProcess)
						{
							status = STATUS_INVALID_PARAMETER;
						}
						else
						{
							status = STATUS_ACCESS_DENIED;
						}
					}
					ObDereferenceObject(pEThread);
				}
			}
		}
	}

	return status;
}

HANDLE __stdcall MyUserGetForegroundWindow(VOID)
/*++

Routine Description:

	if the foreground window is od, then modify
	the return value.

--*/
{
	PEPROCESS pEProcess = NULL;
	HANDLE hRet = NULL;
	ULONG ulProcId = 0;

	hRet = pfOrigUserGetForegroundWindow();
	ulProcId = pfOrigUserQueryWindow(hRet, 0);
	if(NT_SUCCESS( PsLookupProcessByProcessId((HANDLE)ulProcId, &pEProcess) ))
	{
		if(g_dwIsHidenWindow)
		{
			if(!IsProcessInList(IoGetCurrentProcess(), 0, SOD_WHITE_PROCESS))
			{
				if(IsProcessInList(pEProcess, 0, SOD_WHITE_PROCESS))
				{
					hRet = g_hForegroundWindow;
				}
			}
		}

		if(!IsProcessInList(pEProcess, 0, SOD_WHITE_PROCESS))
		{
			g_hForegroundWindow = hRet;
		}

		ObDereferenceObject(pEProcess);
	}

	return hRet;
}

NTSTATUS __stdcall MySetContextThread(
									  HANDLE ThreadHandle,
									  PCONTEXT Context)
/*++

Routine Description:

	if a non-white process wants to modify the debug register,
	then disable it.

--*/
{
	if(!IsProcessInList(IoGetCurrentProcess(), 0, SOD_WHITE_PROCESS)
		&& MmIsAddressValid(Context))	// [Warning:inproper parameters check
	{
		Context->ContextFlags &= ~CONTEXT_DEBUG_REGISTERS;
	}

	return pfOrigSetContextThread(ThreadHandle, Context);
}

NTSTATUS __stdcall MyCreateProcessEx(
									 PHANDLE ProcessHandle,
									 ACCESS_MASK DesiredAccess,
									 POBJECT_ATTRIBUTES ObjectAttributes,
									 HANDLE ParentProcess,
									 ULONG Flags,
									 HANDLE SectionHandle,
									 HANDLE DebugPort,
									 HANDLE ExceptionPort,
									 ULONG InJob)
 /*++
 
 Routine Description:
 
 	see MyCreateProcess.
 
 --*/
{
	NTSTATUS status;
	PVOID ProcessInformation;
	ULONG_PTR	ulValue = 0;

	do 
	{
		if(!IsProcessInList(IoGetCurrentProcess(), 0, SOD_BLACK_PROCESS))
		{
			break;
		}

		if(!NT_SUCCESS(ZwQueryInformationProcess(ZwCurrentProcess(), 
			ProcessDebugFlags, &ProcessInformation,
			4, NULL)))
		{
			break;
		}

		if((ULONG)ProcessInformation != 1)
		{
			break;
		}

		ZwSetInformationProcess(ZwCurrentProcess(), ProcessDebugFlags, &ulValue, 4);
		status = pfOrigCreateProcessEx(ProcessHandle, DesiredAccess,
			ObjectAttributes, ParentProcess, Flags,
			SectionHandle, DebugPort, ExceptionPort, InJob);
		ZwSetInformationProcess(ZwCurrentProcess(), ProcessDebugFlags, &ProcessInformation, 4);
		goto done;

	} while (0);

	status = pfOrigCreateProcessEx(ProcessHandle, DesiredAccess,
		ObjectAttributes, ParentProcess, Flags,
		SectionHandle, DebugPort, ExceptionPort, InJob);

done:
	return status;
}

NTSTATUS __stdcall MyQueryInformationProcess(
	HANDLE ProcessHandle,
	ULONG ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength,
	PULONG ReturnLength)
/*++

Routine Description:

	Hide Debug Port.

--*/
{
	NTSTATUS	status;
	PEPROCESS	pEProcess = NULL;
	PPROCESS_BASIC_INFORMATION	pProcBasicInfo = NULL;

	if(ProcessInformationClass == ProcessTimes &&
		IsProcessInList(IoGetCurrentProcess(), 0, SOD_BLACK_PROCESS))
	{
		status = STATUS_ACCESS_DENIED;
	}
	else
	{
		status = pfOrigQueryInformationProcess(ProcessHandle,
						ProcessInformationClass, ProcessInformation, 
						ProcessInformationLength, ReturnLength);

		if(NT_SUCCESS(status) &&
			!IsProcessInList(IoGetCurrentProcess(), 0, SOD_WHITE_PROCESS))
		{
			if(NT_SUCCESS(ObReferenceObjectByHandle(ProcessHandle, 
				GENERIC_READ, NULL, KernelMode, &pEProcess, NULL)))
			{
				if(IsProcessInList(pEProcess, 0, SOD_BLACK_PROCESS))
				{
					if(ProcessInformationClass == ProcessBasicInformation)
					{
						if(g_ulMajorVer == 6)
						{
							pProcBasicInfo = (PPROCESS_BASIC_INFORMATION)ProcessInformation;
							pProcBasicInfo->InheritedFromUniqueProcessId = g_dwExplorerProcId;
						}
					}
					else if(ProcessInformationClass == ProcessDebugPort)
					{
						// hide debug port
						*(PULONG)ProcessInformation = 0;
					}
					else if(ProcessInformationClass == ProcessDebugObjectHandle)
					{
						ZwClose(*(HANDLE *)ProcessInformation);
						*(HANDLE *)ProcessInformation = NULL;
						status = STATUS_PORT_NOT_SET;
					}
					else if(ProcessInformationClass == ProcessDebugFlags)	// [Warning:add by Bombs]
					{
						*(PULONG)ProcessInformation = 1;
					}
				}
				
				ObDereferenceObject(pEProcess);
			}
		}
	}

	return status;
}

int GetDebugRegisterValue(int RegisterNum)
/*++

Routine Description:

	get debug register value(dr0 ~ dr7)

--*/
{
	int nRet = 0;

	switch(RegisterNum)
	{
	case 0:
		{
			__asm 
			{
				mov eax, dr0
				mov nRet, eax
			}
		}
		break;
	case 1:
		{
			__asm 
			{
				mov eax, dr1
				mov nRet, eax
			}
		}
		break;
	case 2:
		{
			__asm 
			{
				mov eax, dr2
				mov nRet, eax
			}
		}
		break;
	case 3:
		{
			__asm 
			{
				mov eax, dr3
				mov nRet, eax
			}
		}
		break;
	case 6:
		{
			__asm 
			{
				mov eax, dr6
				mov nRet, eax
			}
		}
		break;
	case 7:
		{
			__asm 
			{
				mov eax, dr7
				mov nRet, eax
			}
		}
		break;
	}

	return nRet;
}

VOID __declspec(naked) MyTrap01(VOID)
/*++

Routine Description:

	write the lbr info into the shared memory

--*/
{
	__asm
	{
		// save old and set new
		pusha
		pushf
		push fs
		push ds
		push es
		mov eax, 0x30
		mov fs, ax
		mov eax, 0x23
		mov ds, ax
		mov es, ax

		mov g_pProcInfo, 0
		push 0
		call IoGetCurrentProcess
		push eax
		call GetProcInfoFromList
		mov g_pProcInfo, eax

		cmp g_pProcInfo, 0
		jnz label1
		jmp End1
label1:
		mov eax, g_pProcInfo
		cmp [eax + 8], 1		// black process or not
		jnz short label2
		mov ecx, g_pProcInfo
		cmp [ecx + 0x14], 0		// the pUserAddrOfSharedMem
		jnz short label3
label2:
		jmp End1
label3:
		push 6
		call GetDebugRegisterValue
		mov g_ulDr6, eax
		mov edx, g_ulDr6
		and edx, 4000h		// test the BS bit
		jnz short label4
		jmp End1
label4:
		cmp g_IsEnableLBR, 0
		jnz label5
		jmp short End1

label5:
		// read lbr info and save(from_ip & to_ip)
		push g_pliReg1DB
		push 0x1db
		call ReadMsr
		push g_pliReg1DC
		push 0x1dc
		call ReadMsr
		mov eax, g_pProcInfo
		mov ecx, [eax + 0x14]	// pUserAddrOfSharedMem

		// enable lbr
		mov eax, DWORD PTR g_liReg1DBValue
		mov [ecx], eax
		mov eax, DWORD PTR g_liReg1DCValue
		mov [ecx + 4], eax

		push g_pliDbgCtrlReg
		push 0x1d9
		call ReadMsr
		mov eax, DWORD PTR g_liDbgCtrlRegValue
		or eax, 3	// set btf(Branch trace flag) & lbr(Last branch record)
		mov DWORD PTR g_liDbgCtrlRegValue, eax
		push 0x1d9
		call WriteMsr
		cmp g_ulIsJustRet, 1
		jnz short End1
		jmp short End2

End1:
		pop es
		pop ds
		pop fs
		popf
		popa
		jmp g_ulOldTrap01

End2:
		pop es
		pop ds
		pop fs
		popf
		popa
		iret
	}
}