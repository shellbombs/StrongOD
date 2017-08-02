/*++

Copyright (c) Bombs

Module Name:
	
	DetourFunc.h

Author  :Bombs
Time    :2014-5-8 19:53:38
Abstract:
   
	Header file for DetourFunc.c

--*/

#ifndef _DETOURFUNC_H
#define _DETOURFUNC_H

#include <ntddk.h>

BOOLEAN __stdcall MyUserPostMessage(ULONG hWnd, ULONG Msg, 
								ULONG wParam, ULONG lParam);

NTSTATUS __stdcall MySetInformationThread(HANDLE ThreadHandle,
										ULONG ThreadInformationClass,
										PVOID ThreadInformation,
										ULONG ThreadInformationLength);

NTSTATUS __stdcall MyUserBuildHwndList(
	HANDLE hDesktop,
	HANDLE hWndParent,
	ULONG bChildren,
	ULONG dwThreadId,
	ULONG lParam,
	HANDLE * pWnd,
	ULONG * pBufSize);

NTSTATUS __stdcall MyUserBuildHwndListWin8(
	ULONG a1,
	HANDLE a2,
	ULONG a3,
	ULONG a4,
	ULONG a5,
	ULONG a6,
	HANDLE * a7,
	ULONG * a8);

NTSTATUS __stdcall MyClose(
									  HANDLE Handle);

HANDLE __stdcall MyUserSetParent(
	HANDLE hChild,
	HANDLE hParent);

HANDLE __stdcall MyUserFindWindowEx(
	HANDLE hParent,
	HANDLE hChild,
	PUNICODE_STRING punClassName,
	PUNICODE_STRING punWindowName,
	ULONG dwType);

NTSTATUS __stdcall MyDuplicateObject(
	HANDLE SourceProcessHandle,
	HANDLE SourceHandle,
	HANDLE TargetProcessHandle,
	PHANDLE TargetHandle,
	ACCESS_MASK DesiredAccess,
	ULONG HandleAttributes,
	ULONG Options);

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
	PVOID AttributeList);

NTSTATUS __stdcall MyQueryObject(
	HANDLE ObjectHandle,
	ULONG ObjectInformationClass,
	PVOID ObjectInformation,
	ULONG Length,
	PULONG ReturnLength);

NTSTATUS __stdcall MyQuerySystemInformation(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG Length,
	PULONG ReturnLength);

NTSTATUS __stdcall MyYieldExecution(VOID);

NTSTATUS __stdcall MyCreateProcess(
	PHANDLE ProcessHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	HANDLE ParentProcess,
	BOOLEAN InheritObjectTable,
	HANDLE SectionHandle,
	HANDLE DebugPort,
	HANDLE ExceptionPort);

NTSTATUS __stdcall MyOpenProcess(
	PHANDLE ProcessHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PCLIENT_ID ClientId
	);

ULONG __stdcall MyUserQueryWindow(
	HANDLE hWnd, ULONG Index);

NTSTATUS __stdcall MyOpenThread(
	PHANDLE ThreadHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PCLIENT_ID ClientId);

HANDLE __stdcall MyUserGetForegroundWindow(VOID);

NTSTATUS __stdcall MySetContextThread(
	HANDLE ThreadHandle,
	PCONTEXT Context);

NTSTATUS __stdcall MyCreateProcessEx(
	PHANDLE ProcessHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	HANDLE ParentProcess,
	ULONG Flags,
	HANDLE SectionHandle,
	HANDLE DebugPort,
	HANDLE ExceptionPort,
	ULONG InJob);

NTSTATUS __stdcall MyQueryInformationProcess(
	HANDLE ProcessHandle,
	ULONG ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength,
	PULONG ReturnLength);

VOID MyTrap01(VOID);


NTSTATUS NTKERNELAPI ZwQueryInformationProcess(
	__in          HANDLE ProcessHandle,
	__in          PROCESSINFOCLASS ProcessInformationClass,
	__out         PVOID ProcessInformation,
	__in          ULONG ProcessInformationLength,
	__out_opt     PULONG ReturnLength
	);

NTSTATUS NTKERNELAPI ZwSetInformationProcess(
	HANDLE ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength);

#endif