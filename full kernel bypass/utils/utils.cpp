#include <ntifs.h>
#include "utils.h"


PEPROCESS driver::utils::process_by_name( CHAR* process_name )
{
	PEPROCESS sys_process = PsInitialSystemProcess;
	PEPROCESS cur_entry = sys_process;
	CHAR image_name[15];

	while (cur_entry != sys_process)
	{
		RtlCopyMemory( ( PVOID )( &image_name ), ( PVOID )( ( uintptr_t ) cur_entry + 0x450 ) /*EPROCESS->ImageFileName*/, sizeof( image_name ) );
		if (strstr(image_name, process_name))
		{
			ULONG active_threads;
			RtlCopyMemory( ( PVOID ) &active_threads, ( PVOID )( ( uintptr_t ) cur_entry + 0x498 ) /*EPROCESS->ActiveThreads*/, sizeof( active_threads) ) ;
			if ( active_threads )
			{
				return cur_entry;
				return STATUS_SUCCESS;
			}
		}
		PLIST_ENTRY list = ( PLIST_ENTRY )( ( uintptr_t )( cur_entry ) + 0x2F0 ) /*EPROCESS->ActiveProcessLinks*/;
		cur_entry = ( PEPROCESS )( ( uintptr_t )list->Flink - 0x2F0 );
	} 
}