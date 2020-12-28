#include <ntifs.h>

extern "C"
{

	NTKERNELAPI PVOID
		PsGetProcessSectionBaseAddress(
			PEPROCESS Process
		);

}

#pragma once
#define _USE_MATH_DEFINES
#include <math.h>

#if defined(__GNUC__)
typedef          long long ll;
typedef unsigned long long ull;
#define __int64 long long
#define __int32 int
#define __int16 short
#define __int8  char
#define MAKELL(num) num ## LL
#define FMT_64 "ll"
#elif defined(_MSC_VER)
typedef          __int64 ll;
typedef unsigned __int64 ull;
#define MAKELL(num) num ## i64
#define FMT_64 "I64"
#elif defined (__BORLANDC__)
typedef          __int64 ll;
typedef unsigned __int64 ull;
#define MAKELL(num) num ## i64
#define FMT_64 "L"
#else
#error "unknown compiler"
#endif
typedef unsigned int uint;
typedef unsigned char uchar;
typedef unsigned short ushort;
//typedef unsigned long ulong;

typedef          char   int8;
typedef   signed char   sint8;
typedef unsigned char   uint8;
typedef          short  int16;
typedef   signed short  sint16;
typedef unsigned short  uint16;
typedef          int    int32;
typedef   signed int    sint32;
typedef unsigned int    uint32;
typedef ll              int64;
typedef ll              sint64;
typedef ull             uint64;

// Partially defined types:
#define _BYTE  uint8
#define _WORD  uint16
#define _DWORD uint32
#define _QWORD uint64
#if !defined(_MSC_VER)
#define _LONGLONG __int128
#endif


// Some convenience macros to make partial accesses nicer
// first unsigned macros:
//Already defined
//#define LOBYTE(x)   (*((_BYTE*)&(x)))   // low byte
//#define LOWORD(x)   (*((_WORD*)&(x)))   // low word
//#define LODWORD(x)  (*((_DWORD*)&(x)))  // low dword
//#define HIBYTE(x)   (*((_BYTE*)&(x)+1))
//#define HIWORD(x)   (*((_WORD*)&(x)+1))
#define HIDWORD(x)  (*((_DWORD*)&(x)+1))
#define BYTEn(x, n)   (*((_BYTE*)&(x)+n))
#define WORDn(x, n)   (*((_WORD*)&(x)+n))
#define BYTE1(x)   BYTEn(x,  1)         // byte 1 (counting from 0)
#define BYTE2(x)   BYTEn(x,  2)
#define BYTE3(x)   BYTEn(x,  3)
#define BYTE4(x)   BYTEn(x,  4)
#define BYTE5(x)   BYTEn(x,  5)
#define BYTE6(x)   BYTEn(x,  6)
#define BYTE7(x)   BYTEn(x,  7)
#define BYTE8(x)   BYTEn(x,  8)
#define BYTE9(x)   BYTEn(x,  9)
#define BYTE10(x)  BYTEn(x, 10)
#define BYTE11(x)  BYTEn(x, 11)
#define BYTE12(x)  BYTEn(x, 12)
#define BYTE13(x)  BYTEn(x, 13)
#define BYTE14(x)  BYTEn(x, 14)
#define BYTE15(x)  BYTEn(x, 15)
#define WORD1(x)   WORDn(x,  1)
#define WORD2(x)   WORDn(x,  2)         // third word of the object, unsigned
#define WORD3(x)   WORDn(x,  3)
#define WORD4(x)   WORDn(x,  4)
#define WORD5(x)   WORDn(x,  5)
#define WORD6(x)   WORDn(x,  6)
#define WORD7(x)   WORDn(x,  7)

// now signed macros (the same but with sign extension)
#define SLOBYTE(x)   (*((int8*)&(x)))
#define SLOWORD(x)   (*((int16*)&(x)))
#define SLODWORD(x)  (*((int32*)&(x)))
#define SHIBYTE(x)   (*((int8*)&(x)+1))
#define SHIWORD(x)   (*((int16*)&(x)+1))
#define SHIDWORD(x)  (*((int32*)&(x)+1))
#define SBYTEn(x, n)   (*((int8*)&(x)+n))
#define SWORDn(x, n)   (*((int16*)&(x)+n))
#define SBYTE1(x)   SBYTEn(x,  1)
#define SBYTE2(x)   SBYTEn(x,  2)
#define SBYTE3(x)   SBYTEn(x,  3)
#define SBYTE4(x)   SBYTEn(x,  4)
#define SBYTE5(x)   SBYTEn(x,  5)
#define SBYTE6(x)   SBYTEn(x,  6)
#define SBYTE7(x)   SBYTEn(x,  7)
#define SBYTE8(x)   SBYTEn(x,  8)
#define SBYTE9(x)   SBYTEn(x,  9)
#define SBYTE10(x)  SBYTEn(x, 10)
#define SBYTE11(x)  SBYTEn(x, 11)
#define SBYTE12(x)  SBYTEn(x, 12)
#define SBYTE13(x)  SBYTEn(x, 13)
#define SBYTE14(x)  SBYTEn(x, 14)
#define SBYTE15(x)  SBYTEn(x, 15)
#define SWORD1(x)   SWORDn(x,  1)
#define SWORD2(x)   SWORDn(x,  2)
#define SWORD3(x)   SWORDn(x,  3)
#define SWORD4(x)   SWORDn(x,  4)
#define SWORD5(x)   SWORDn(x,  5)
#define SWORD6(x)   SWORDn(x,  6)
#define SWORD7(x)   SWORDn(x,  7)

template<class T> T __ROL__(T value, int count)
{
    const uint nbits = sizeof(T) * 8;

    if (count > 0)
    {
        count %= nbits;
        T high = value >> (nbits - count);
        if (T(-1) < 0) // signed value
            high &= ~((T(-1) << count));
        value <<= count;
        value |= high;
    }
    else
    {
        count = -count % nbits;
        T low = value << (nbits - count);
        value >>= count;
        value |= low;
    }
    return value;
}

inline uint8  __ROL1__(uint8  value, int count) { return __ROL__((uint8)value, count); }
inline uint16 __ROL2__(uint16 value, int count) { return __ROL__((uint16)value, count); }
inline uint32 __ROL4__(uint32 value, int count) { return __ROL__((uint32)value, count); }
inline uint64 __ROL8__(uint64 value, int count) { return __ROL__((uint64)value, count); }
inline uint8  __ROR1__(uint8  value, int count) { return __ROL__((uint8)value, -count); }
inline uint16 __ROR2__(uint16 value, int count) { return __ROL__((uint16)value, -count); }
inline uint32 __ROR4__(uint32 value, int count) { return __ROL__((uint32)value, -count); }
inline uint64 __ROR8__(uint64 value, int count) { return __ROL__((uint64)value, -count); }

//Dumb glow decryption stuff
//https://www.codeproject.com/Articles/1274943/IEEE-754-Conversion

#define NTH_BIT(b, n) ((b >> n) & 0x1)

#define BYTE_TO_BIN(b)   (( b & 0x80 ) ) |\
            (( b & 0x40 ) ) |\
            (( b & 0x20 ) ) |\
            (( b & 0x10 ) ) |\
            (( b & 0x08 ) ) |\
            (( b & 0x04 ) ) |\
            (( b & 0x02 ) ) |\
            ( b & 0x01 )

#define MANTISSA_TO_BIN(b)  (( b & 0x400000 ) ) |\
             (( b & 0x200000 ) ) |\
             (( b & 0x100000 ) ) |\
             (( b &  0x80000 ) ) |\
             (( b &  0x40000 ) ) |\
             (( b &  0x20000 ) ) |\
             (( b &  0x10000 ) ) |\
             (( b &  0x8000 ) ) |\
             (( b &  0x4000 ) ) |\
             (( b &  0x2000 ) ) |\
             (( b &  0x1000 ) ) |\
             (( b &  0x800 ) ) |\
             (( b &  0x400 ) ) |\
             (( b &  0x200 ) ) |\
             (( b &  0x100 ) ) |\
             (( b &  0x80 ) ) |\
             (( b &  0x40 ) ) |\
             (( b &  0x20 ) ) |\
             (( b &  0x10 ) ) |\
             (( b &  0x08 ) ) |\
             (( b &  0x04 ) ) |\
             (( b &  0x02 ) ) |\
              ( b & 0x01 )

typedef union IEEE754
{
    struct
    {
        unsigned int mantissa : 23;
        unsigned int exponent : 8;
        unsigned int sign : 1;
    } raw;
    float f;
} IEEE754;

typedef struct _MM_UNLOADED_DRIVER
{
    UNICODE_STRING     Name;
    PVOID             ModuleStart;
    PVOID             ModuleEnd;
    ULONG64         UnloadTime;
} MM_UNLOADED_DRIVER, * PMM_UNLOADED_DRIVER;
typedef struct _PIDDBCACHE_ENTRY
{
    LIST_ENTRY        List;
    UNICODE_STRING    DriverName;
    ULONG            TimeDateStamp;
    NTSTATUS        LoadStatus;
    char            _0x0028[16];
} PIDDBCACHE_ENTRY, * PPIDDBCACHE_ENTRY;
typedef struct _SYSTEM_MODULEE
{
    ULONG_PTR Reserved[2];
    PVOID     Base;
    ULONG     Size;
    ULONG     Flags;
    USHORT    Index;
    USHORT    Unknown;
    USHORT    LoadCount;
    USHORT    ModuleNameOffset;
    CHAR      ImageName[256];
} SYSTEM_MODULEE, * PSYSTEM_MODULEE;
typedef struct _SYSTEM_MODULE_INFORMATIONN
{
    ULONG_PTR     ModuleCount;
    SYSTEM_MODULEE Modules[1];
} SYSTEM_MODULE_INFORMATIONN, * PSYSTEM_MODULE_INFORMATIONN;
typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation,				   // q: SYSTEM_BASIC_INFORMATION
	SystemProcessorInformation,			   // q: SYSTEM_PROCESSOR_INFORMATION
	SystemPerformanceInformation,		   // q: SYSTEM_PERFORMANCE_INFORMATION
	SystemTimeOfDayInformation,			   // q: SYSTEM_TIMEOFDAY_INFORMATION
	SystemPathInformation,				   // not implemented
	SystemProcessInformation,			   // q: SYSTEM_PROCESS_INFORMATION
	SystemCallCountInformation,			   // q: SYSTEM_CALL_COUNT_INFORMATION
	SystemDeviceInformation,			   // q: SYSTEM_DEVICE_INFORMATION
	SystemProcessorPerformanceInformation, // q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION
	SystemFlagsInformation,				   // q: SYSTEM_FLAGS_INFORMATION
	SystemCallTimeInformation,			   // not implemented // SYSTEM_CALL_TIME_INFORMATION // 10
	SystemModuleInformation,			   // q: RTL_PROCESS_MODULES
	SystemLocksInformation,				   // q: SYSTEM_LOCK_INFORMATION
	SystemStackTraceInformation,
	SystemPagedPoolInformation,			   // not implemented
	SystemNonPagedPoolInformation,		   // not implemented
	SystemHandleInformation,			   // q: SYSTEM_HANDLE_INFORMATION
	SystemObjectInformation,			   // q: SYSTEM_OBJECTTYPE_INFORMATION mixed with SYSTEM_OBJECT_INFORMATION
	SystemPageFileInformation,			   // q: SYSTEM_PAGEFILE_INFORMATION
	SystemVdmInstemulInformation,		   // q
	SystemVdmBopInformation,			   // not implemented // 20
	SystemFileCacheInformation,			   // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemCache)
	SystemPoolTagInformation,			   // q: SYSTEM_POOLTAG_INFORMATION
	SystemInterruptInformation,			   // q: SYSTEM_INTERRUPT_INFORMATION
	SystemDpcBehaviorInformation,		   // q: SYSTEM_DPC_BEHAVIOR_INFORMATION; s: SYSTEM_DPC_BEHAVIOR_INFORMATION (requires SeLoadDriverPrivilege)
	SystemFullMemoryInformation,		   // not implemented
	SystemLoadGdiDriverInformation,		   // s (kernel-mode only)
	SystemUnloadGdiDriverInformation,	  // s (kernel-mode only)
	SystemTimeAdjustmentInformation,	   // q: SYSTEM_QUERY_TIME_ADJUST_INFORMATION; s: SYSTEM_SET_TIME_ADJUST_INFORMATION (requires SeSystemtimePrivilege)
	SystemSummaryMemoryInformation,		   // not implemented
	SystemMirrorMemoryInformation,		   // s (requires license value "Kernel-MemoryMirroringSupported") (requires SeShutdownPrivilege) // 30
	SystemPerformanceTraceInformation,	 // s
	SystemObsolete0,					   // not implemented
	SystemExceptionInformation,			   // q: SYSTEM_EXCEPTION_INFORMATION
	SystemCrashDumpStateInformation,	   // s (requires SeDebugPrivilege)
	SystemKernelDebuggerInformation,	   // q: SYSTEM_KERNEL_DEBUGGER_INFORMATION
	SystemContextSwitchInformation,		   // q: SYSTEM_CONTEXT_SWITCH_INFORMATION
	SystemRegistryQuotaInformation,		   // q: SYSTEM_REGISTRY_QUOTA_INFORMATION; s (requires SeIncreaseQuotaPrivilege)
	SystemExtendServiceTableInformation,   // s (requires SeLoadDriverPrivilege) // loads win32k only
	SystemPrioritySeperation,			   // s (requires SeTcbPrivilege)
	SystemVerifierAddDriverInformation,	// s (requires SeDebugPrivilege) // 40
	SystemVerifierRemoveDriverInformation, // s (requires SeDebugPrivilege)
	SystemProcessorIdleInformation,		   // q: SYSTEM_PROCESSOR_IDLE_INFORMATION
	SystemLegacyDriverInformation,		   // q: SYSTEM_LEGACY_DRIVER_INFORMATION
	SystemCurrentTimeZoneInformation,	  // q
	SystemLookasideInformation,			   // q: SYSTEM_LOOKASIDE_INFORMATION
	SystemTimeSlipNotification,			   // s (requires SeSystemtimePrivilege)
	SystemSessionCreate,				   // not implemented
	SystemSessionDetach,				   // not implemented
	SystemSessionInformation,			   // not implemented
	SystemRangeStartInformation,		   // q: SYSTEM_RANGE_START_INFORMATION // 50
	SystemVerifierInformation,			   // q: SYSTEM_VERIFIER_INFORMATION; s (requires SeDebugPrivilege)
	SystemVerifierThunkExtend,			   // s (kernel-mode only)
	SystemSessionProcessInformation,	   // q: SYSTEM_SESSION_PROCESS_INFORMATION
	SystemLoadGdiDriverInSystemSpace,	  // s (kernel-mode only) (same as SystemLoadGdiDriverInformation)
	SystemNumaProcessorMap,				   // q
	SystemPrefetcherInformation,		   // q: PREFETCHER_INFORMATION; s: PREFETCHER_INFORMATION // PfSnQueryPrefetcherInformation
	SystemExtendedProcessInformation,	  // q: SYSTEM_PROCESS_INFORMATION
	SystemRecommendedSharedDataAlignment,  // q
	SystemComPlusPackage,				   // q; s
	SystemNumaAvailableMemory,			   // 60
	SystemProcessorPowerInformation,	   // q: SYSTEM_PROCESSOR_POWER_INFORMATION
	SystemEmulationBasicInformation,	   // q
	SystemEmulationProcessorInformation,
	SystemExtendedHandleInformation,			   // q: SYSTEM_HANDLE_INFORMATION_EX
	SystemLostDelayedWriteInformation,			   // q: ULONG
	SystemBigPoolInformation,					   // q: SYSTEM_BIGPOOL_INFORMATION
	SystemSessionPoolTagInformation,			   // q: SYSTEM_SESSION_POOLTAG_INFORMATION
	SystemSessionMappedViewInformation,			   // q: SYSTEM_SESSION_MAPPED_VIEW_INFORMATION
	SystemHotpatchInformation,					   // q; s
	SystemObjectSecurityMode,					   // q // 70
	SystemWatchdogTimerHandler,					   // s (kernel-mode only)
	SystemWatchdogTimerInformation,				   // q (kernel-mode only); s (kernel-mode only)
	SystemLogicalProcessorInformation,			   // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION
	SystemWow64SharedInformationObsolete,		   // not implemented
	SystemRegisterFirmwareTableInformationHandler, // s (kernel-mode only)
	SystemFirmwareTableInformation,				   // SYSTEM_FIRMWARE_TABLE_INFORMATION
	SystemModuleInformationEx,					   // q: RTL_PROCESS_MODULE_INFORMATION_EX
	SystemVerifierTriageInformation,			   // not implemented
	SystemSuperfetchInformation,				   // q; s: SUPERFETCH_INFORMATION // PfQuerySuperfetchInformation
	SystemMemoryListInformation,				   // q: SYSTEM_MEMORY_LIST_INFORMATION; s: SYSTEM_MEMORY_LIST_COMMAND (requires SeProfileSingleProcessPrivilege) // 80
	SystemFileCacheInformationEx,				   // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (same as SystemFileCacheInformation)
	SystemThreadPriorityClientIdInformation,	   // s: SYSTEM_THREAD_CID_PRIORITY_INFORMATION (requires SeIncreaseBasePriorityPrivilege)
	SystemProcessorIdleCycleTimeInformation,	   // q: SYSTEM_PROCESSOR_IDLE_CYCLE_TIME_INFORMATION[]
	SystemVerifierCancellationInformation,		   // not implemented // name:wow64:whNT32QuerySystemVerifierCancellationInformation
	SystemProcessorPowerInformationEx,			   // not implemented
	SystemRefTraceInformation,					   // q; s: SYSTEM_REF_TRACE_INFORMATION // ObQueryRefTraceInformation
	SystemSpecialPoolInformation,				   // q; s (requires SeDebugPrivilege) // MmSpecialPoolTag, then MmSpecialPoolCatchOverruns != 0
	SystemProcessIdInformation,					   // q: SYSTEM_PROCESS_ID_INFORMATION
	SystemErrorPortInformation,					   // s (requires SeTcbPrivilege)
	SystemBootEnvironmentInformation,			   // q: SYSTEM_BOOT_ENVIRONMENT_INFORMATION // 90
	SystemHypervisorInformation,				   // q; s (kernel-mode only)
	SystemVerifierInformationEx,				   // q; s: SYSTEM_VERIFIER_INFORMATION_EX
	SystemTimeZoneInformation,					   // s (requires SeTimeZonePrivilege)
	SystemImageFileExecutionOptionsInformation,	// s: SYSTEM_IMAGE_FILE_EXECUTION_OPTIONS_INFORMATION (requires SeTcbPrivilege)
	SystemCoverageInformation,					   // q; s // name:wow64:whNT32QuerySystemCoverageInformation; ExpCovQueryInformation
	SystemPrefetchPatchInformation,				   // not implemented
	SystemVerifierFaultsInformation,			   // s (requires SeDebugPrivilege)
	SystemSystemPartitionInformation,			   // q: SYSTEM_SYSTEM_PARTITION_INFORMATION
	SystemSystemDiskInformation,				   // q: SYSTEM_SYSTEM_DISK_INFORMATION
	SystemProcessorPerformanceDistribution,		   // q: SYSTEM_PROCESSOR_PERFORMANCE_DISTRIBUTION // 100
	SystemNumaProximityNodeInformation,			   // q
	SystemDynamicTimeZoneInformation,			   // q; s (requires SeTimeZonePrivilege)
	SystemCodeIntegrityInformation,				   // q: SYSTEM_CODEINTEGRITY_INFORMATION // SeCodeIntegrityQueryInformation
	SystemProcessorMicrocodeUpdateInformation,	 // s
	SystemProcessorBrandString,					   // q // HaliQuerySystemInformation -> HalpGetProcessorBrandString, info class 23
	SystemVirtualAddressInformation,			   // q: SYSTEM_VA_LIST_INFORMATION[]; s: SYSTEM_VA_LIST_INFORMATION[] (requires SeIncreaseQuotaPrivilege) // MmQuerySystemVaInformation
	SystemLogicalProcessorAndGroupInformation,	 // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX // since WIN7 // KeQueryLogicalProcessorRelationship
	SystemProcessorCycleTimeInformation,		   // q: SYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION[]
	SystemStoreInformation,						   // q; s // SmQueryStoreInformation
	SystemRegistryAppendString,					   // s: SYSTEM_REGISTRY_APPEND_STRING_PARAMETERS // 110
	SystemAitSamplingValue,						   // s: ULONG (requires SeProfileSingleProcessPrivilege)
	SystemVhdBootInformation,					   // q: SYSTEM_VHD_BOOT_INFORMATION
	SystemCpuQuotaInformation,					   // q; s // PsQueryCpuQuotaInformation
	SystemNativeBasicInformation,				   // not implemented
	SystemSpare1,								   // not implemented
	SystemLowPriorityIoInformation,				   // q: SYSTEM_LOW_PRIORITY_IO_INFORMATION
	SystemTpmBootEntropyInformation,			   // q: TPM_BOOT_ENTROPY_NT_RESULT // ExQueryTpmBootEntropyInformation
	SystemVerifierCountersInformation,			   // q: SYSTEM_VERIFIER_COUNTERS_INFORMATION
	SystemPagedPoolInformationEx,				   // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypePagedPool)
	SystemSystemPtesInformationEx,				   // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemPtes) // 120
	SystemNodeDistanceInformation,				   // q
	SystemAcpiAuditInformation,					   // q: SYSTEM_ACPI_AUDIT_INFORMATION // HaliQuerySystemInformation -> HalpAuditQueryResults, info class 26
	SystemBasicPerformanceInformation,			   // q: SYSTEM_BASIC_PERFORMANCE_INFORMATION // name:wow64:whNtQuerySystemInformation_SystemBasicPerformanceInformation
	SystemQueryPerformanceCounterInformation,	  // q: SYSTEM_QUERY_PERFORMANCE_COUNTER_INFORMATION // since WIN7 SP1
	SystemSessionBigPoolInformation,			   // q: SYSTEM_SESSION_POOLTAG_INFORMATION // since WIN8
	SystemBootGraphicsInformation,				   // q; s: SYSTEM_BOOT_GRAPHICS_INFORMATION (kernel-mode only)
	SystemScrubPhysicalMemoryInformation,
	SystemBadPageInformation,
	SystemProcessorProfileControlArea,
	SystemCombinePhysicalMemoryInformation, // 130
	SystemEntropyInterruptTimingCallback,
	SystemConsoleInformation,		 // q: SYSTEM_CONSOLE_INFORMATION
	SystemPlatformBinaryInformation, // q: SYSTEM_PLATFORM_BINARY_INFORMATION
	SystemThrottleNotificationInformation,
	SystemHypervisorProcessorCountInformation, // q: SYSTEM_HYPERVISOR_PROCESSOR_COUNT_INFORMATION
	SystemDeviceDataInformation,			   // q: SYSTEM_DEVICE_DATA_INFORMATION
	SystemDeviceDataEnumerationInformation,
	SystemMemoryTopologyInformation,		 // q: SYSTEM_MEMORY_TOPOLOGY_INFORMATION
	SystemMemoryChannelInformation,			 // q: SYSTEM_MEMORY_CHANNEL_INFORMATION
	SystemBootLogoInformation,				 // q: SYSTEM_BOOT_LOGO_INFORMATION // 140
	SystemProcessorPerformanceInformationEx, // q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION_EX // since WINBLUE
	SystemSpare0,
	SystemSecureBootPolicyInformation, // q: SYSTEM_SECUREBOOT_POLICY_INFORMATION
	SystemPageFileInformationEx,	   // q: SYSTEM_PAGEFILE_INFORMATION_EX
	SystemSecureBootInformation,	   // q: SYSTEM_SECUREBOOT_INFORMATION
	SystemEntropyInterruptTimingRawInformation,
	SystemPortableWorkspaceEfiLauncherInformation, // q: SYSTEM_PORTABLE_WORKSPACE_EFI_LAUNCHER_INFORMATION
	SystemFullProcessInformation,				   // q: SYSTEM_PROCESS_INFORMATION with SYSTEM_PROCESS_INFORMATION_EXTENSION (requires admin)
	SystemKernelDebuggerInformationEx,			   // q: SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX
	SystemBootMetadataInformation,				   // 150
	SystemSoftRebootInformation,
	SystemElamCertificateInformation, // s: SYSTEM_ELAM_CERTIFICATE_INFORMATION
	SystemOfflineDumpConfigInformation,
	SystemProcessorFeaturesInformation, // q: SYSTEM_PROCESSOR_FEATURES_INFORMATION
	SystemRegistryReconciliationInformation,
	SystemEdidInformation,
	SystemManufacturingInformation,			 // q: SYSTEM_MANUFACTURING_INFORMATION // since THRESHOLD
	SystemEnergyEstimationConfigInformation, // q: SYSTEM_ENERGY_ESTIMATION_CONFIG_INFORMATION
	SystemHypervisorDetailInformation,		 // q: SYSTEM_HYPERVISOR_DETAIL_INFORMATION
	SystemProcessorCycleStatsInformation,	// q: SYSTEM_PROCESSOR_CYCLE_STATS_INFORMATION // 160
	SystemVmGenerationCountInformation,
	SystemTrustedPlatformModuleInformation, // q: SYSTEM_TPM_INFORMATION
	SystemKernelDebuggerFlags,
	SystemCodeIntegrityPolicyInformation, // q: SYSTEM_CODEINTEGRITYPOLICY_INFORMATION
	SystemIsolatedUserModeInformation,	// q: SYSTEM_ISOLATED_USER_MODE_INFORMATION
	SystemHardwareSecurityTestInterfaceResultsInformation,
	SystemSingleModuleInformation, // q: SYSTEM_SINGLE_MODULE_INFORMATION
	SystemAllowedCpuSetsInformation,
	SystemDmaProtectionInformation,		   // q: SYSTEM_DMA_PROTECTION_INFORMATION
	SystemInterruptCpuSetsInformation,	 // q: SYSTEM_INTERRUPT_CPU_SET_INFORMATION // 170
	SystemSecureBootPolicyFullInformation, // q: SYSTEM_SECUREBOOT_POLICY_FULL_INFORMATION
	SystemCodeIntegrityPolicyFullInformation,
	SystemAffinitizedInterruptProcessorInformation,
	SystemRootSiloInformation,  // q: SYSTEM_ROOT_SILO_INFORMATION
	SystemCpuSetInformation,	// q: SYSTEM_CPU_SET_INFORMATION // since THRESHOLD2
	SystemCpuSetTagInformation, // q: SYSTEM_CPU_SET_TAG_INFORMATION
	SystemWin32WerStartCallout,
	SystemSecureKernelProfileInformation,			// q: SYSTEM_SECURE_KERNEL_HYPERGUARD_PROFILE_INFORMATION
	SystemCodeIntegrityPlatformManifestInformation, // q: SYSTEM_SECUREBOOT_PLATFORM_MANIFEST_INFORMATION // since REDSTONE
	SystemInterruptSteeringInformation,				// 180
	SystemSupportedProcessorArchitectures,
	SystemMemoryUsageInformation,			   // q: SYSTEM_MEMORY_USAGE_INFORMATION
	SystemCodeIntegrityCertificateInformation, // q: SYSTEM_CODEINTEGRITY_CERTIFICATE_INFORMATION
	MaxSystemInfoClass
} SYSTEM_INFORMATION_CLASS;

extern "C"
NTKERNELAPI NTSTATUS NTAPI
ZwQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

inline auto dereference(uintptr_t address, unsigned int offset) -> uintptr_t
{
    if (address == 0)
        return 0;

    return address + (int)((*(int*)(address + offset) + offset) + sizeof(int));
}
inline auto relative(uintptr_t address, unsigned int size) -> PVOID
{
    if (address == 0)
        return 0;

    return ((PVOID)((unsigned char*)(address)+*(int*)((unsigned char*)(address)+((size)-(INT)sizeof(INT))) + (size)));
}
inline auto compare_data(const unsigned char* pData, const unsigned char* bMask, const char* szMask) -> bool
{
    for (; *szMask; ++szMask, ++pData, ++bMask)
        if (*szMask == 'x' && *pData != *bMask)
            return 0;

    return (*szMask) == 0;
}
inline auto find_pattern2(UINT64 dwAddress, UINT64 dwLen, unsigned char* bMask, const char* szMask) -> ULONGLONG
{
    for (ULONGLONG i = 0; i < dwLen; i++)
        if (compare_data((unsigned char*)(dwAddress + i), bMask, szMask))
            return (ULONGLONG)(dwAddress + i);

    return 0;
}
template <typename t = void*>
inline auto find_pattern(void* start, size_t length, const char* pattern, const char* mask) -> t
{
    const auto data = static_cast<const char*>(start);
    const auto pattern_length = strlen(mask);

    for (size_t i = 0; i <= length - pattern_length; i++)
    {
        bool accumulative_found = true;

        for (size_t j = 0; j < pattern_length; j++)
        {
            if (!MmIsAddressValid(reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(data) + i + j)))
            {
                accumulative_found = false;
                break;
            }

            if (data[i + j] != pattern[j] && mask[j] != '?')
            {
                accumulative_found = false;
                break;
            }
        }

        if (accumulative_found)
        {
            return (t)(reinterpret_cast<uintptr_t>(data) + i);
        }
    }

    return (t)nullptr;
}