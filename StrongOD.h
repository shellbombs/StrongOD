/*++

Copyright (c) Bombs

Module Name:
	
	StrongOD.h

Author  :Bombs
Time    :2014-4-29 16:24:50
Abstract:
   
	The main header file for the driver

--*/

#ifndef _STRONGOD_H
#define _STRONGOD_H

#include <ntddk.h>

// function declarations
NTSTATUS CommDispatch(PDEVICE_OBJECT pDeviceObject, PIRP pIrp);
VOID DriverUnload(PDRIVER_OBJECT pDriverObject);
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath);

#endif