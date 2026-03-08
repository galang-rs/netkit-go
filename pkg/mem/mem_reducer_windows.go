//go:build windows

package mem

import (
	"context"
	"fmt"
	"log"
	"runtime/debug"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Constants for Windows Native API
const (
	SystemMemoryListInformation = 80 // 0x50
)

// SYSTEM_MEMORY_LIST_COMMAND constants from memreduct source
const (
	MemoryCaptureAccessedBits              = 0
	MemoryCaptureAndResetAccessedBits      = 1
	MemoryEmptyWorkingSets                 = 2
	MemoryFlushModifiedList                = 3
	MemoryPurgeLowPriorityReadCache        = 4
	MemoryClearVerifyRequiredPages         = 5
	MemoryPurgeStandbyList                 = 6
	MemoryPurgeUnusedPages                 = 7
	MemoryDecodePreFetchCache              = 8
	MemoryPurgeCombinePages                = 9
	MemoryPurgeLowPriorityRespurposedPages = 10
)

var (
	modntdll                   = windows.NewLazySystemDLL("ntdll.dll")
	procNtSetSystemInformation = modntdll.NewProc("NtSetSystemInformation")

	modadvapi32               = windows.NewLazySystemDLL("advapi32.dll")
	procOpenProcessToken      = modadvapi32.NewProc("OpenProcessToken")
	procLookupPrivilegeValue  = modadvapi32.NewProc("LookupPrivilegeValueW")
	procAdjustTokenPrivileges = modadvapi32.NewProc("AdjustTokenPrivileges")

	modkernel32                  = windows.NewLazySystemDLL("kernel32.dll")
	procSetProcessWorkingSetSize = modkernel32.NewProc("SetProcessWorkingSetSize")
	procGetProcessHeap           = modkernel32.NewProc("GetProcessHeap")
	procHeapCompact              = modkernel32.NewProc("HeapCompact")

	modpsapi            = windows.NewLazySystemDLL("psapi.dll")
	procEmptyWorkingSet = modpsapi.NewProc("EmptyWorkingSet")

	procGlobalMemoryStatusEx = modkernel32.NewProc("GlobalMemoryStatusEx")
)

// MEMORYSTATUSEX structure for GlobalMemoryStatusEx
type memoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

type WindowsReducer struct{}

func getReducer() Reducer {
	return &WindowsReducer{}
}

// SetPrivilege enables a specific privilege for the current process.
func (r *WindowsReducer) SetPrivilege(name string, enable bool) error {
	var token windows.Token
	handle := windows.CurrentProcess()
	err := windows.OpenProcessToken(handle, windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token)
	if err != nil {
		return err
	}
	defer token.Close()

	var luid windows.LUID
	err = windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr(name), &luid)
	if err != nil {
		return err
	}

	tp := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges: [1]windows.LUIDAndAttributes{
			{
				Luid:       luid,
				Attributes: 0,
			},
		},
	}
	if enable {
		tp.Privileges[0].Attributes = windows.SE_PRIVILEGE_ENABLED
	}

	err = windows.AdjustTokenPrivileges(token, false, &tp, 0, nil, nil)
	if err != nil {
		return err
	}

	return nil
}

// Reduce performs system-level memory optimization on Windows.
func (r *WindowsReducer) Reduce() {
	handle := windows.CurrentProcess()

	// 1. Trim the process working set (Process Working Set)
	ret, _, _ := procSetProcessWorkingSetSize.Call(uintptr(handle), ^uintptr(0), ^uintptr(0))
	if ret != 0 {
		log.Printf("[MEM] Local process working set trimmed")
	}

	// 2. Try to empty working set via PSAPI
	ret, _, _ = procEmptyWorkingSet.Call(uintptr(handle))
	if ret != 0 {
		log.Printf("[MEM] Local working set emptied")
	}

	// 3. Advanced cleaning (Standby / Modified lists)
	// Requires Administrator privileges and SeProfileSingleProcessPrivilege
	if err := r.SetPrivilege("SeProfileSingleProcessPrivilege", true); err != nil {
		log.Printf("[MEM] Failed to enable SeProfileSingleProcessPrivilege (likely no admin or privilege not held): %v", err)
	} else {
		log.Printf("[MEM] Enabled SeProfileSingleProcessPrivilege")

		// Full cleaning commands used by memreduct
		commands := []uint32{
			MemoryEmptyWorkingSets,
			MemoryFlushModifiedList,
			MemoryPurgeStandbyList,
			MemoryPurgeLowPriorityReadCache,
			MemoryPurgeUnusedPages,
			MemoryPurgeCombinePages,
		}

		for _, cmd := range commands {
			status, _, _ := procNtSetSystemInformation.Call(
				uintptr(SystemMemoryListInformation),
				uintptr(unsafe.Pointer(&cmd)),
				uintptr(unsafe.Sizeof(cmd)),
			)

			// status 0 is STATUS_SUCCESS
			if status == 0 {
				log.Printf("[MEM] Successfully executed memory command: %d", cmd)
			} else {
				// 0xC0000022 is STATUS_ACCESS_DENIED, etc.
				log.Printf("[MEM] Memory command %d: status 0x%x", cmd, status)
			}
		}
	}

	// 4. Defrag Local Heap (HeapCompact)
	hHeap, _, _ := procGetProcessHeap.Call()
	if hHeap != 0 {
		ret, _, _ = procHeapCompact.Call(hHeap, 0)
		if ret != 0 {
			log.Printf("[MEM] Local heap defragmented (compacted)")
		}
	}

	// 5. Return memory to OS (Go Runtime optimization)
	debug.FreeOSMemory()

	log.Printf("[MEM] Memory reduction & defrag cycle completed")
}

// GetSystemStats retrieves system-wide memory metrics on Windows.
func (r *WindowsReducer) GetSystemStats() (*SystemStats, error) {
	var ms memoryStatusEx
	ms.Length = uint32(unsafe.Sizeof(ms))

	ret, _, err := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&ms)))
	if ret == 0 {
		return nil, fmt.Errorf("GlobalMemoryStatusEx failed: %v", err)
	}

	return &SystemStats{
		TotalPhysMB:     ms.TotalPhys / 1024 / 1024,
		AvailPhysMB:     ms.AvailPhys / 1024 / 1024,
		TotalVirtualMB:  ms.TotalVirtual / 1024 / 1024,
		AvailVirtualMB:  ms.AvailVirtual / 1024 / 1024,
		MemoryLoad:      ms.MemoryLoad,
		TotalPageFileMB: ms.TotalPageFile / 1024 / 1024,
		AvailPageFileMB: ms.AvailPageFile / 1024 / 1024,
	}, nil
}

// StartPeriodic runs the memory reduction at specified intervals.
func (r *WindowsReducer) StartPeriodic(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		log.Printf("[MEM] Periodic memory reduction started (Interval: %v)", interval)
		for {
			select {
			case <-ctx.Done():
				log.Printf("[MEM] Periodic memory reduction stopped")
				return
			case <-ticker.C:
				r.Reduce()
			}
		}
	}()
}
