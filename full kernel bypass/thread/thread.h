
namespace driver
{
	namespace thread
	{
		bool unlink();
		bool link();

		bool terminate_thread = true;
		int total_loops = 0;
		int loops_before_end = 2;
	}
}