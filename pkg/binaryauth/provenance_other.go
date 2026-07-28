//go:build !darwin && !linux

package binaryauth

func platformProvenance(string) (string, string, error) { return "", "", nil }
