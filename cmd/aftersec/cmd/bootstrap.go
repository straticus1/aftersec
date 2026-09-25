package cmd

import (
	"fmt"
	"strings"

	"aftersec/pkg/bootstrap"
	"github.com/spf13/cobra"
)

func init() {
	var keyPath, version, out string
	var osName, arch string
	var files []string
	sign := &cobra.Command{
		Use:   "sign",
		Short: "Hash a release and sign its bootstrap manifest offline",
		Annotations: map[string]string{
			"skipConfig": "true",
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 0 {
				return fmt.Errorf("bootstrap sign does not take positional arguments")
			}
			key, err := bootstrap.LoadSigningKey(keyPath)
			if err != nil {
				return err
			}
			release := make([]bootstrap.ReleaseFile, 0, len(files))
			for _, spec := range files {
				file, err := parseReleaseFile(spec, osName, arch)
				if err != nil {
					return err
				}
				release = append(release, file)
			}
			return bootstrap.Publish(key, version, out, release)
		},
	}
	sign.Flags().StringVar(&keyPath, "key", "", "PKCS#8 Ed25519 private key file")
	sign.Flags().StringVar(&version, "version", "", "release version")
	sign.Flags().StringVar(&out, "out", "", "directory for the manifest, public key, and artifacts")
	sign.Flags().StringVar(&osName, "os", "", "darwin, linux, or windows")
	sign.Flags().StringVar(&arch, "arch", "", "arm64 or amd64")
	sign.Flags().StringArrayVar(&files, "file", nil, "name=path, repeated once per artifact")
	if err := sign.MarkFlagRequired("key"); err != nil {
		panic(err)
	}
	if err := sign.MarkFlagRequired("version"); err != nil {
		panic(err)
	}
	if err := sign.MarkFlagRequired("out"); err != nil {
		panic(err)
	}
	if err := sign.MarkFlagRequired("os"); err != nil {
		panic(err)
	}
	if err := sign.MarkFlagRequired("arch"); err != nil {
		panic(err)
	}
	if err := sign.MarkFlagRequired("file"); err != nil {
		panic(err)
	}
	parent := &cobra.Command{
		Use:   "bootstrap",
		Short: "Offline bootstrap release tools",
		Annotations: map[string]string{
			"skipConfig": "true",
		},
	}
	parent.AddCommand(sign)
	rootCmd.AddCommand(parent)
}

func parseReleaseFile(spec, osName, arch string) (bootstrap.ReleaseFile, error) {
	name, path, ok := strings.Cut(spec, "=")
	if !ok || name == "" || path == "" || strings.Contains(name, "=") {
		return bootstrap.ReleaseFile{}, fmt.Errorf("bootstrap file must be name=path")
	}
	return bootstrap.ReleaseFile{Name: name, OS: osName, Arch: arch, Path: path}, nil
}
