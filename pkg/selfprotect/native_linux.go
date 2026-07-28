//go:build linux

package selfprotect

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type inodeKey struct {
	Device uint64
	Inode  uint64
}

type linuxNativeGuard struct {
	collection *ebpf.Collection
	links      []link.Link
}

func (g *linuxNativeGuard) Close() error {
	for _, item := range g.links {
		_ = item.Close()
	}
	g.collection.Close()
	return nil
}

func StartNativeGuard(paths []string, objectPath string) (io.Closer, error) {
	info, err := os.Stat(objectPath)
	if err != nil {
		return nil, fmt.Errorf("stat self-protection BPF object: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("self-protection BPF object permissions are unsafe")
	}
	spec, err := ebpf.LoadCollectionSpec(objectPath)
	if err != nil {
		return nil, fmt.Errorf("load self-protection BPF spec: %w", err)
	}
	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("load self-protection BPF collection: %w", err)
	}
	guard := &linuxNativeGuard{collection: collection}
	fail := func(cause error) (io.Closer, error) {
		_ = guard.Close()
		return nil, cause
	}
	protected := collection.Maps["protected_inodes"]
	agentPID := collection.Maps["agent_tgid"]
	if protected == nil || agentPID == nil {
		return fail(fmt.Errorf("self-protection BPF object is missing policy maps"))
	}
	index := uint32(0)
	pid := uint32(os.Getpid())
	if err := agentPID.Update(&index, &pid, ebpf.UpdateAny); err != nil {
		return fail(fmt.Errorf("set self-protection recovery PID: %w", err))
	}
	count := 0
	for _, root := range paths {
		err := filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			count++
			if count > 100000 {
				return fmt.Errorf("protected inode capacity exceeded")
			}
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok {
				return fmt.Errorf("read protected inode identity")
			}
			key := inodeKey{Device: uint64(stat.Dev), Inode: stat.Ino}
			value := uint8(1)
			return protected.Update(&key, &value, ebpf.UpdateAny)
		})
		if err != nil {
			return fail(fmt.Errorf("load protected path %s: %w", root, err))
		}
	}
	for _, name := range []string{
		"protect_file_permission", "protect_inode_create",
		"protect_inode_unlink", "protect_inode_rename",
	} {
		program := collection.Programs[name]
		if program == nil {
			return fail(fmt.Errorf("self-protection BPF object is missing %s", name))
		}
		item, err := link.AttachLSM(link.LSMOptions{Program: program})
		if err != nil {
			return fail(fmt.Errorf("attach %s: %w", name, err))
		}
		guard.links = append(guard.links, item)
	}
	return guard, nil
}
