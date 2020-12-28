#include <ntifs.h>
#include <stdio.h>
#include <stdarg.h> 
#include <ntimage.h>
#include "memory.h"

extern "C" 
NTSTATUS NTAPI MmCopyVirtualMemory
(
	PEPROCESS		SourceProcess,
	PVOID			SourceAddress,
	PEPROCESS		TargetProcess,
	PVOID			TargetAddress,
	SIZE_T			BufferSize,
	KPROCESSOR_MODE PreviousMode,
	PSIZE_T			ReturnSize
);

NTSTATUS driver::memory::read_virtual_memory( ULONG pid, PEPROCESS process, PVOID source_address, PVOID target_address, SIZE_T size )
{
	SIZE_T bytes = 0;
	if ( NT_SUCCESS( MmCopyVirtualMemory( process, source_address, PsGetCurrentProcess(), target_address, size, KernelMode, &bytes ) ) )
		return STATUS_SUCCESS;

	return STATUS_UNSUCCESSFUL;
}

NTSTATUS  driver::memory::write_virtual_memory( ULONG pid, PEPROCESS process, PVOID source_address, PVOID target_address, SIZE_T size )
{
	SIZE_T bytes = 0;
	if ( NT_SUCCESS ( MmCopyVirtualMemory( PsGetCurrentProcess(), source_address, process, target_address, size, KernelMode, &bytes ) ) )
		return STATUS_SUCCESS;

	return STATUS_UNSUCCESSFUL;
}
