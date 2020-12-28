#include <ntifs.h>
#include <ntimage.h>
#include <ntddk.h>
#include "defs.h"
#include "io/io.h"
#include "utils/utils.h"
#include "memory/memory.h"
#include "thread/thread.h"
#include "cleaning/cleaning.h"
using namespace driver;

void driver_thread( void* context )
{
	// allow five seconds for driver to finish entry
	utils::sleep(5000);
	
	// debug text
	io::dbgprint( "cleaning status -> %i", cleaning::clean_traces( ) );
	io::dbgprint( "tid -> %i", PsGetCurrentThreadId( ) );

	// user extersize
	bool status = thread::unlink( );
	io::dbgprint( "unlinked thread -> %i", status );

	// change your process name here
	process::process_name = "RainbowSix.exe";
	io::dbgprint( "process name -> %s", process::process_name );

	// scuff check to check if our peprocess is valid
	while ( utils::process_by_name( process::process_name, &process::process ) == STATUS_NOT_FOUND)
	{
		io::dbgprint( "waiting for -> %s", process::process_name );
		utils::sleep(2000);
	}
	io::dbgprint("found process -> %s", process::process_name);

	// sleep for 15 seconds to allow game to get started and prevent us from getting false info
	utils::sleep(15000);

	utils::process_by_name( process::process_name, &process::process );
	io::dbgprint( "peprocess -> 0x%llx", process::process );

	process::pid = reinterpret_cast< uint32 >( PsGetProcessId( process::process ) );
	io::dbgprint("pid -> %i", process::pid);

	process::base_address = reinterpret_cast < uint64 >( PsGetProcessSectionBaseAddress( process::process ) );
	io::dbgprint( "base address -> 0x%llx", process::base_address );

	// main loop
	while ( true )
	{
		
		//example read
		uint64 round_manager = memory::read< uint64 >( process::base_address + 0x77BF800 );
		uint32 encrypted_round_state = memory::read< uint32 >( round_manager + 0xC0 );
		uint32 decrypted_round_state = _rotl64( encrypted_round_state - 0x56, 0x1E );
		io::dbgprint( "round state ptr -> 0x%llx", decrypted_round_state );

		// example write
		memory::write< uint32 >( round_manager + 0xC0, 0x0 );

		// for testing
		if ( thread::terminate_thread ) 
		{
			io::dbgprint( "loops -> %i", thread::total_loops );
			utils::sleep( 5000 );
			thread::total_loops++;

			if ( thread::total_loops > thread::loops_before_end )
			{
				io::dbgprint( "terminating thread" );
				PsTerminateSystemThread( STATUS_SUCCESS );
			}
		}
	}
	PsTerminateSystemThread( STATUS_SUCCESS );
}

NTSTATUS DriverEntry( PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path ) {
	UNREFERENCED_PARAMETER( driver_object );
	UNREFERENCED_PARAMETER( registry_path );

	io::dbgprint("driver entry called.");

	// change this per mapper; debug prints the entire mmu
	cleaning::debug = false;
	cleaning::driver_timestamp = 0x5284EAC3;
	cleaning::driver_name = RTL_CONSTANT_STRING(L"iqvw64e.sys");

	HANDLE thread_handle = nullptr;
	OBJECT_ATTRIBUTES object_attribues{ };
	InitializeObjectAttributes( &object_attribues, nullptr, OBJ_KERNEL_HANDLE, nullptr, nullptr );

	NTSTATUS status = PsCreateSystemThread( &thread_handle, 0, &object_attribues, nullptr, nullptr, reinterpret_cast< PKSTART_ROUTINE >( &driver_thread ), nullptr );
	io::dbgprint("thread status -> 0x%llx", status);

	io::dbgprint("fininshed driver entry... closing...");
        
	return STATUS_SUCCESS;
}

