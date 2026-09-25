package preserve

import "crypto/sha256"

func sha256Sum(body []byte) [sha256.Size]byte {
	return sha256.Sum256(body)
}
