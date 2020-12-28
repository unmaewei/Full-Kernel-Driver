#define MM_UNLOADED_DRIVERS_SIZE 50

namespace driver
{
	namespace cleaning
	{

		bool clean_traces( );
		bool verify_piddb( );
		bool clean_piddb( );
		bool verify_mmu( );
		bool clean_mmu( );

		UNICODE_STRING driver_name;
		int driver_timestamp;
		bool debug;
	}
}