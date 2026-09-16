package binaryauth

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

const maxExecutableBytes int64 = 1 << 34

func InspectExecutable(path string) (Executable, error) {
	before, err := os.Stat(path)
	if err != nil {
		return Executable{}, fmt.Errorf("stat executable: %w", err)
	}
	if !before.Mode().IsRegular() {
		return Executable{}, fmt.Errorf("executable is not a regular file")
	}
	if before.Size() > maxExecutableBytes {
		return Executable{}, fmt.Errorf("executable exceeds size limit")
	}
	file, err := os.Open(path)
	if err != nil {
		return Executable{}, fmt.Errorf("open executable: %w", err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) || !opened.Mode().IsRegular() {
		return Executable{}, fmt.Errorf("executable changed while opening")
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(file, maxExecutableBytes+1))
	if err != nil {
		return Executable{}, fmt.Errorf("hash executable: %w", err)
	}
	if n > maxExecutableBytes {
		return Executable{}, fmt.Errorf("executable exceeds size limit")
	}
	identity := Executable{SHA256: hex.EncodeToString(hash.Sum(nil))}
	teamID, packageName, err := platformProvenance(path)
	if err != nil {
		return Executable{}, err
	}
	after, err := file.Stat()
	current, pathErr := os.Stat(path)
	if err != nil || pathErr != nil || !os.SameFile(opened, current) ||
		opened.Size() != n || after.Size() != n || current.Size() != n ||
		!opened.ModTime().Equal(after.ModTime()) || !opened.ModTime().Equal(current.ModTime()) {
		return Executable{}, fmt.Errorf("executable changed during authorization")
	}
	identity.TeamID = teamID
	identity.Package = packageName
	return identity, nil
}
