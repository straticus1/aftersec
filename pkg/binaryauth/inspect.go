package binaryauth

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

func InspectExecutable(path string) (Executable, error) {
	before, err := os.Stat(path)
	if err != nil || !before.Mode().IsRegular() {
		return Executable{}, fmt.Errorf("stat executable: %w", err)
	}
	file, err := os.Open(path)
	if err != nil {
		return Executable{}, fmt.Errorf("open executable: %w", err)
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, io.LimitReader(file, 1<<34)); err != nil {
		_ = file.Close()
		return Executable{}, fmt.Errorf("hash executable: %w", err)
	}
	if err := file.Close(); err != nil {
		return Executable{}, err
	}
	after, err := os.Stat(path)
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() ||
		!before.ModTime().Equal(after.ModTime()) {
		return Executable{}, fmt.Errorf("executable changed during authorization")
	}
	identity := Executable{SHA256: hex.EncodeToString(hash.Sum(nil))}
	teamID, packageName, err := platformProvenance(path)
	if err != nil {
		return Executable{}, err
	}
	identity.TeamID = teamID
	identity.Package = packageName
	return identity, nil
}
