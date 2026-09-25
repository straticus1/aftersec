package displayframes

import (
	"bytes"
	"image"
	"image/jpeg"
	"os"
	"path/filepath"
	"testing"
)

func TestStoreRejectsEscapeAndSymlink(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	img := image.NewRGBA(image.Rect(0, 0, 2, 2))
	var buf bytes.Buffer
	if err = jpeg.Encode(&buf, img, &jpeg.Options{Quality: 40}); err != nil {
		t.Fatal(err)
	}
	const command = "0123456789abcdef0123456789abcdef"
	if err = store.Save("../other", "ep", command, buf.Bytes()); err == nil {
		t.Fatal("escaped tenant stored")
	}
	if err = store.Save("org", "HW-host", command, buf.Bytes()); err != nil {
		t.Fatal(err)
	}
	f, err := store.Open("org", "HW-host", command)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	path := filepath.Join(dir, "org", "HW-host", command+".jpg")
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink("/etc/passwd", path); err != nil {
		t.Fatal(err)
	}
	if _, err = store.Open("org", "HW-host", command); err == nil {
		t.Fatal("symlink frame opened")
	}
}
