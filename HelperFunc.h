/*++

Copyright (c) Bombs

Module Name:
	
	HelperFunc.h

Author  :Bombs
Time    :2014-4-29 16:32:16
Abstract:
   
	the header file for HelperFunc.c, Contains function declarations

--*/

#ifndef _HELPERFUNC_H
#define _HELPERFUNC_H

#include <ntddk.h>
#include "CommDef.h"

HANDLE GetCsrssProcId();

HANDLE GetProcIdByName(wchar_t * szProcName);

PVOID GetServiceDescriptorTableShadowAddr();

VOID ProcCreateNotify(
						IN HANDLE  ParentId,
						IN HANDLE  ProcessId,
						IN BOOLEAN  Create
						);
						
VOID SSDTHookInit();

BOOLEAN IsProcessInList(PEPROCESS pEProcess,
					ULONG hProcId,
					DWORD dwType);
					
PLIST_NODE GetProcInfoFromList(PEPROCESS pEProcess, ULONG hProcId);

ULONG AddProcInfoToList(PEPROCESS pEProcess, ULONG hProcId, DWORD dwType);

BOOLEAN DelProcInfoFromList(PEPROCESS pEProcess, ULONG hProcId, DWORD dwType);

ULONG GetProcCount(DWORD dwType);

int GetFunctionIndex(char * szFunctionName, PUNICODE_STRING punModuleName);

PVOID GetOrigFunctionAddr(DWORD dwFuncIndex, DWORD dwType);

VOID HookSSDT();

VOID UnhookSSDT();

VOID HookINT1();

VOID UnhookINT1();

VOID EncAndDecBuffer(PVOID pBuffer, ULONG ulLen);

VOID ReadMsr(int RegisterAddr, LARGE_INTEGER * pliValue);
VOID WriteMsr(int RegisterAddr, LARGE_INTEGER * pliValue);

extern LARGE_INTEGER g_liDbgCtrlRegValue;
extern PLARGE_INTEGER g_pliDbgCtrlReg;
extern ULONG	g_ulOldTrap01;

//
// function prototype for hook
//

typedef BOOLEAN (__stdcall *PF_UserPostMessage)(ULONG hWnd, DWORD Msg, 
				ULONG wParam, ULONG lParam);
extern PF_UserPostMessage pfOrigUserPostMessage;
extern PF_UserPostMessage pfMyUserPostMessage;
				
typedef NTSTATUS (__stdcall *PF_SetInformationThread)(HANDLE ThreadHandle,
				ULONG ThreadInformationClass,
				PVOID ThreadInformation,
				ULONG ThreadInformationLength);
extern PF_SetInformationThread pfOrigSetInformationThread;
extern PF_SetInformationThread pfMySetInformationThread;
				
typedef NTSTATUS (__stdcall *PF_UserBuildHwndList)(
				HANDLE hDesktop,
				HANDLE hWndParent,
				ULONG bChildren,
				ULONG dwThreadId,
				ULONG lParam,
				HANDLE * pWnd,
				ULONG * pBufSize);
extern PF_UserBuildHwndList pfOrigUserBuildHwndList;
extern PF_UserBuildHwndList pfMyUserBuildHwndList;
				
typedef NTSTATUS (__stdcall *PF_UserBuildHwndListWin8)(
				ULONG a1,
				HANDLE a2,
				ULONG a3,
				ULONG a4,
				ULONG a5,
				ULONG a6,
				HANDLE * a7,
				ULONG * a8);
extern PF_UserBuildHwndListWin8 pfOrigUserBuildHwndListWin8;
extern PF_UserBuildHwndListWin8 pfMyUserBuildHwndListWin8;
				
typedef NTSTATUS (__stdcall *PF_Close)(
				HANDLE Handle);
extern PF_Close	pfOrigClose;
extern PF_Close	pfMyClose;

typedef HANDLE (__stdcall *PF_UserSetParent)(
				HANDLE hChild,
				HANDLE hParent);
extern PF_UserSetParent	pfOrigUserSetParent;
extern PF_UserSetParent	pfMyUserSetParent;
				
typedef HANDLE (__stdcall *PF_UserFindWindowEx)(
				HANDLE hParent,
				HANDLE hChild,
				PUNICODE_STRING punClassName,
				PUNICODE_STRING punWindowName,
				ULONG dwType);
extern PF_UserFindWindowEx pfOrigUserFindWindowEx;
extern PF_UserFindWindowEx pfMyUserFindWindowEx;
				
typedef NTSTATUS (__stdcall *PF_DuplicateObject)(
				HANDLE SourceProcessHandle,
				HANDLE SourceHandle,
				HANDLE TargetProcessHandle,
				PHANDLE TargetHandle,
				ACCESS_MASK DesiredAccess,
				ULONG HandleAttributes,
				ULONG Options);
extern PF_DuplicateObject	pfOrigDuplicateObject;
extern PF_DuplicateObject	pfMyDuplicateObject;
				
typedef NTSTATUS (__stdcall *PF_CreateUserProcess)(
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
extern PF_CreateUserProcess pfOrigCreateUserProcess;
extern PF_CreateUserProcess pfMyCreateUserProcess;
				
typedef NTSTATUS (__stdcall *PF_QueryObject)(
				HANDLE ObjectHandle,
				ULONG ObjectInformationClass,
				PVOID ObjectInformation,
				ULONG Length,
				PULONG ReturnLength);
extern PF_QueryObject	pfOrigQueryObject;
extern PF_QueryObject	pfMyQueryObject;
				
typedef NTSTATUS (__stdcall *PF_QuerySystemInformation)(
				ULONG SystemInformationClass,
				PVOID SystemInformation,
				ULONG Length,
				PULONG ReturnLength);
extern PF_QuerySystemInformation pfOrigQuerySystemInformation;
extern PF_QuerySystemInformation pfMyQuerySystemInformation;
				
typedef NTSTATUS (__stdcall *PF_YieldExecution)();
extern PF_YieldExecution pfOrigYieldExecution;
extern PF_YieldExecution pfMyYieldExecution;

typedef NTSTATUS (__stdcall *PF_CreateProcess)(
				PHANDLE ProcessHandle,
				ACCESS_MASK DesiredAccess,
				POBJECT_ATTRIBUTES ObjectAttributes,
				HANDLE ParentProcess,
				BOOLEAN InheritObjectTable,
				HANDLE SectionHandle,
				HANDLE DebugPort,
				HANDLE ExceptionPort);
extern PF_CreateProcess pfOrigCreateProcess;
extern PF_CreateProcess pfMyCreateProcess;
				
typedef NTSTATUS (__stdcall *PF_OpenProcess)(
				PHANDLE ProcessHandle,
				ACCESS_MASK DesiredAccess,
				POBJECT_ATTRIBUTES ObjectAttributes,
				PCLIENT_ID ClientId
				);
extern PF_OpenProcess pfOrigOpenProcess;
extern PF_OpenProcess pfMyOpenProcess;
				
typedef ULONG (__stdcall *PF_UserQueryWindow)(
				HANDLE hWnd, DWORD Index);
extern PF_UserQueryWindow pfOrigUserQueryWindow;
extern PF_UserQueryWindow pfMyUserQueryWindow;
				
typedef NTSTATUS (__stdcall *PF_OpenThread)(
				PHANDLE ThreadHandle,
				ACCESS_MASK DesiredAccess,
				POBJECT_ATTRIBUTES ObjectAttributes,
				PCLIENT_ID ClientId);
extern PF_OpenThread	pfOrigOpenThread;
extern PF_OpenThread	pfMyOpenThread;
				
typedef HANDLE (__stdcall *PF_UserGetForegroundWindow)();
extern PF_UserGetForegroundWindow pfOrigUserGetForegroundWindow;
extern PF_UserGetForegroundWindow pfMyUserGetForegroundWindow;

typedef NTSTATUS (__stdcall *PF_SetContextThread)(
				HANDLE ThreadHandle,
				PCONTEXT Context);
extern PF_SetContextThread pfOrigSetContextThread;
extern PF_SetContextThread pfMySetContextThread;
				
typedef NTSTATUS (__stdcall *PF_CreateProcessEx)(
				PHANDLE ProcessHandle,
				ACCESS_MASK DesiredAccess,
				POBJECT_ATTRIBUTES ObjectAttributes,
				HANDLE ParentProcess,
				ULONG Flags,
				HANDLE SectionHandle,
				HANDLE DebugPort,
				HANDLE ExceptionPort,
				ULONG InJob);
extern PF_CreateProcessEx pfOrigCreateProcessEx;
extern PF_CreateProcessEx pfMyCreateProcessEx;
				
typedef NTSTATUS (__stdcall *PF_QueryInformationProcess)(
				HANDLE ProcessHandle,
				ULONG ProcessInformationClass,
				PVOID ProcessInformation,
				ULONG ProcessInformationLength,
				PULONG ReturnLength);
extern PF_QueryInformationProcess pfOrigQueryInformationProcess;
extern PF_QueryInformationProcess pfMyQueryInformationProcess;

extern DWORD	g_dwExitTimeOffsetInEProcess;
extern DWORD	g_dwSmssProcId;
extern ULONG	g_ulOldTrap01;

//
// unducumented structures and functions declarations
//

typedef enum _SYSTEM_INFORMATION_CLASS   
{   
	SystemBasicInformation,                 //  0 Y N   
	SystemProcessorInformation,             //  1 Y N   
	SystemPerformanceInformation,           //  2 Y N   
	SystemTimeOfDayInformation,             //  3 Y N   
	SystemNotImplemented1,                  //  4 Y N   
	SystemProcessesAndThreadsInformation,   //  5 Y N  
	SystemCallCounts,                       //  6 Y N   
	SystemConfigurationInformation,         //  7 Y N   
	SystemProcessorTimes,                   //  8 Y N   
	SystemGlobalFlag,                       //  9 Y Y   
	SystemNotImplemented2,                  // 10 Y N   
	SystemModuleInformation,                // 11 Y N   
	SystemLockInformation,                  // 12 Y N   
	SystemNotImplemented3,                  // 13 Y N   
	SystemNotImplemented4,                  // 14 Y N   
	SystemNotImplemented5,                  // 15 Y N   
	SystemHandleInformation,                // 16 Y N   
	SystemObjectInformation,                // 17 Y N   
	SystemPagefileInformation,              // 18 Y N   
	SystemInstructionEmulationCounts,       // 19 Y N   
	SystemInvalidInfoClass1,                // 20   
	SystemCacheInformation,                 // 21 Y Y   
	SystemPoolTagInformation,               // 22 Y N   
	SystemProcessorStatistics,              // 23 Y N   
	SystemDpcInformation,                   // 24 Y Y   
	SystemNotImplemented6,                  // 25 Y N   
	SystemLoadImage,                        // 26 N Y   
	SystemUnloadImage,                      // 27 N Y   
	SystemTimeAdjustment,                   // 28 Y Y   
	SystemNotImplemented7,                  // 29 Y N   
	SystemNotImplemented8,                  // 30 Y N   
	SystemNotImplemented9,                  // 31 Y N   
	SystemCrashDumpInformation,             // 32 Y N   
	SystemExceptionInformation,             // 33 Y N   
	SystemCrashDumpStateInformation,        // 34 Y Y/N   
	SystemKernelDebuggerInformation,        // 35 Y N   
	SystemContextSwitchInformation,         // 36 Y N   
	SystemRegistryQuotaInformation,         // 37 Y Y   
	SystemLoadAndCallImage,                 // 38 N Y   
	SystemPrioritySeparation,               // 39 N Y   
	SystemNotImplemented10,                 // 40 Y N   
	SystemNotImplemented11,                 // 41 Y N  
	SystemInvalidInfoClass2,                // 42   
	SystemInvalidInfoClass3,                // 43   
	SystemTimeZoneInformation,              // 44 Y N   
	SystemLookasideInformation,             // 45 Y N   
	SystemSetTimeSlipEvent,                 // 46 N Y   
	SystemCreateSession,                    // 47 N Y   
	SystemDeleteSession,                    // 48 N Y   
	SystemInvalidInfoClass4,                // 49   
	SystemRangeStartInformation,            // 50 Y N   
	SystemVerifierInformation,              // 51 Y Y   
	SystemAddVerifier,                      // 52 N Y   
	SystemSessionProcessesInformation       // 53 Y N   
} SYSTEM_INFORMATION_CLASS;   

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO{
	//USHORT UniqueProcessId;
	//USHORT CreatorBackTraceIndex;
	ULONG ProcessId;
	UCHAR ObjectTypeIndex;
	UCHAR HandleAttributes;
	USHORT HandleValue;
	PVOID Object;
	ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG	NumberOfHandles;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
}SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

//typedef enum _OBJECT_INFORMATION_CLASS{
//	ObjectBasicInformation,
//	ObjectNameInformation,
//	ObjectTypeInformation,
//	ObjectAllInformation,
//	ObjectDataInformation
//}OBJECT_INFORMATION_CLASS;

NTSTATUS NTKERNELAPI ZwQuerySystemInformation(
				SYSTEM_INFORMATION_CLASS SystemInformationClass,
				PVOID SystemInformation,
				ULONG SystemInformationLength,
				PULONG ReturnLength);

// NTSTATUS NTKERNELAPI ZwDuplicateObject(
// 				IN HANDLE			SourceProcessHandle,
// 				IN PVOID          SourceHandle,
// 				IN HANDLE           TargetProcessHandle,
// 				OUT PHANDLE         TargetHandle,
// 				IN ACCESS_MASK      DesiredAccess OPTIONAL,
// 				IN BOOLEAN          InheritHandle,
// 				IN ULONG            Options);

// NTSTATUS NTKERNELAPI ZwQueryObject(
// 								  HANDLE Handle,
// 						          OBJECT_INFORMATION_CLASS ObjectInformationClass,
// 								  PVOID ObjectInformation,
// 						          ULONG ObjectInformationLength,
// 								  PULONG ReturnLength);

typedef struct _SYSTEM_PROCANDTHREAD_INFORMATION
{
	ULONG NextEntryDelta;
	ULONG ThreadCount;
	ULONG Reserved1[6];
	LARGE_INTEGER ftCreateTime;
	LARGE_INTEGER ftUserTime;
	LARGE_INTEGER ftKernelTime;
	UNICODE_STRING ProcessName;
	ULONG BasePriority;
	ULONG ProcessId;
	ULONG InheritedFromProcessId;
	ULONG HandleCount;
	ULONG Reserved2[2];
	ULONG VmCounters;
	ULONG dCommitCharge;
	PVOID ThreadInfos[1];
}SYSTEM_PROCANDTHREAD_INFORMATION, *PSYSTEM_PROCANDTHREAD_INFORMATION;

typedef struct _SYS_MODULE
{
	ULONG	Reserved1;
	ULONG	Reserved2;
	PVOID	ImageBaseAddress;
	ULONG	ImageSize;
	ULONG	Flags;
	USHORT	Id;
	USHORT	Rank;
	USHORT	w018;
	USHORT	NameOffset;
	UCHAR	Name[256];
}SYSTEM_MODULE, *PSYSTEM_MODULE;

typedef struct _SYSTEM_MODULE_INFORMATION
{
	ULONG ModulesCount;
	SYSTEM_MODULE Modules[0];
}SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

BOOLEAN NTKERNELAPI KeAddSystemServiceTable(
							PULONG_PTR Base,
							PULONG Count,
							ULONG Limit,
							PUCHAR Number,
							ULONG Index);

KAFFINITY NTKERNELAPI KeSetAffinityThread(
			PKTHREAD Thread,
			KAFFINITY Affinity);

#endif