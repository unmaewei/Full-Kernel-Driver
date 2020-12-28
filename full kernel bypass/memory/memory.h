#include "../process/process.h"

namespace driver
{
	namespace memory
	{
		NTSTATUS read_virtual_memory( ULONG pid, PEPROCESS process, PVOID source_address, PVOID target_address, SIZE_T size );
		NTSTATUS write_virtual_memory( ULONG pid, PEPROCESS process, PVOID source_address, PVOID target_address, SIZE_T size );

		template< typename T >
		T read( uintptr_t address )
		{
			T buffer{};
			read_virtual_memory( process::pid, process::process, (void*)address, &buffer, sizeof(T) );
			return buffer;
		}

		template< typename T >
		void write( uintptr_t address, T buffer )
		{
			write_virtual_memory( process::pid, process::process, (void*)address, &buffer, sizeof(T) );
		}
	};
}