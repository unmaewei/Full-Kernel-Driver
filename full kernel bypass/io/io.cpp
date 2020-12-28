#include <ntifs.h>
#include <stdio.h>
#include <stdarg.h> 
#include <ntimage.h>
#include "io.h"

void driver::io::dbgprint( PCCH format, ...)
{
	CHAR message[512];
	va_list _valist;
	va_start(_valist, format);
	const ULONG N = _vsnprintf_s(message, sizeof(message) - 1, format, _valist);
	message[N] = L'\0';

	vDbgPrintExWithPrefix("[Kernel Driver] ", DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, message, _valist);

	va_end(_valist);
}
