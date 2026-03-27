package forensics

import (
	"context"
	"debug/macho"
	"fmt"
	"log"
	"time"

	"github.com/unicorn-engine/unicorn/bindings/go/unicorn"
)

type EmulationReport struct {
	Architecture   string `json:"architecture"`
	Instructions   uint64 `json:"instructions"`
	Syscalls       int    `json:"syscalls"`
	UnpackingLoops int    `json:"unpacking_loops"`
	Score          int    `json:"score"`
	HasError       bool   `json:"has_error"`
	ErrorMessage   string `json:"error_message,omitempty"`
}

// EmulateMachO isolates and executes the active .text segment of a macOS binary
// entirely within an emulated CPU (Unicorn) to heuristically baseline packing routines.
func EmulateMachO(ctx context.Context, path string) (*EmulationReport, error) {
	report := &EmulationReport{}

	// Protect against long-hanging infinite loops in the sandbox
	_, cancel := context.WithTimeout(ctx, 30*time.Second) // wait, time.Second requires "time"
	defer cancel()

	f, err := macho.Open(path)
	if err != nil {
		return nil, fmt.Errorf("not a valid macho binary: %w", err)
	}
	defer f.Close()

	var arch int
	var mode int
	if f.Cpu == macho.CpuArm64 {
		report.Architecture = "ARM64"
		arch = unicorn.ARCH_ARM64
		mode = unicorn.MODE_ARM
	} else if f.Cpu == macho.CpuAmd64 {
		report.Architecture = "x86_64"
		arch = unicorn.ARCH_X86
		mode = unicorn.MODE_64
	} else {
		report.Architecture = f.Cpu.String()
		return report, fmt.Errorf("architecture %s not currently supported for deep emulation", report.Architecture)
	}

	mu, err := unicorn.NewUnicorn(arch, mode)
	if err != nil {
		return report, fmt.Errorf("failed to initialize unicorn engine: %w", err)
	}
	defer mu.Close()

	// Locate the __text section to map into our virtual CPU
	textSec := f.Section("__text")
	if textSec == nil {
		return report, fmt.Errorf("no __text section found in binary")
	}

	codeBytes, err := textSec.Data()
	if err != nil {
		return report, fmt.Errorf("failed to read __text data: %w", err)
	}

	// Align to 4KB page size for Unicorn memory mapping
	const PAGE_SIZE = 4096
	address := uint64(textSec.Addr) &^ (PAGE_SIZE - 1)
	size := uint64(len(codeBytes))
	// Pad size to nearest page
	paddedSize := (size + PAGE_SIZE - 1) &^ (PAGE_SIZE - 1)
	if paddedSize == 0 {
		paddedSize = PAGE_SIZE // Minimum 1 page
	}

	// Map the memory
	if err := mu.MemMap(address, paddedSize); err != nil {
		return report, fmt.Errorf("failed to map memory at 0x%x (size %d): %w", address, paddedSize, err)
	}

	// Write the executable code
	if err := mu.MemWrite(uint64(textSec.Addr), codeBytes); err != nil {
		return report, fmt.Errorf("failed to write __text to mapped memory: %w", err)
	}

	// Hook block execution to detect potential loops (highly indicative of unpacking stubs)
	blockCount := 0
	mu.HookAdd(unicorn.HOOK_BLOCK, func(mu unicorn.Unicorn, addr uint64, size uint32) {
		blockCount++
		if blockCount > 500 {
			report.UnpackingLoops++
			// Excessive basic block loops without syscalls often signify decryption/unpacking logic
			report.Score += 2
		}
	}, 1, 0)

	// Hook code to count executed instructions
	mu.HookAdd(unicorn.HOOK_CODE, func(mu unicorn.Unicorn, addr uint64, size uint32) {
		report.Instructions++
		
		// SVC instruction on ARM64 is 01 00 00 d4
		// INT 0x80 or SYSCALL on x86_64
		if report.Architecture == "x86_64" {
			mem, _ := mu.MemRead(addr, 2)
			if len(mem) == 2 && mem[0] == 0x0f && mem[1] == 0x05 {
				report.Syscalls++
				report.Score += 5
			}
		} else if report.Architecture == "ARM64" {
			mem, _ := mu.MemRead(addr, 4)
			if len(mem) == 4 && mem[0] == 0x01 && mem[1] == 0x00 && mem[2] == 0x00 && mem[3] == 0xd4 {
				report.Syscalls++
				report.Score += 5
			}
		}
		
		// Stop execution early if we have enough heuristics
		if report.Instructions >= 2048 {
			mu.Stop()
		}
	}, 1, 0)

	// Start emulation from the base of __text
	log.Printf("🔬 [EMULATOR] Initiating Mach-O Unicorn execution sandbox for %d bytes...", len(codeBytes))
	err = mu.Start(uint64(textSec.Addr), uint64(textSec.Addr)+uint64(len(codeBytes)))
	if err != nil {
		// Emulation almost always errors on unmapped memory accesses since we only mapped __text.
		// For heuristic purposes, we absorb the crash and use the instruction count gathered before the crash.
		report.HasError = true
		report.ErrorMessage = err.Error()
		
		// Give minor score bump for obfuscated code that crashes our generic sandbox immediately
		if report.Instructions < 5 {
			report.Score += 10 
		}
	}

	// Final clamp on heuristic score
	if report.Score > 100 {
		report.Score = 100
	}

	log.Printf("✅ [EMULATOR] Execution finished. Insts: %d, Syscalls: %d, Loops: %d, Score: %d", 
		report.Instructions, report.Syscalls, report.UnpackingLoops, report.Score)

	return report, nil
}
