
namespace driver
{
	namespace utils
	{
		PEPROCESS process_by_name( CHAR* process_name );

		void sleep(int ms) { LARGE_INTEGER time;  time.QuadPart =- (ms) * 10 * 1000; KeDelayExecutionThread(KernelMode, TRUE, &time); }
	}
}