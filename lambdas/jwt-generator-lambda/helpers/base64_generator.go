package helpers

import "encoding/base64"

func Base64URL(input []byte) string {
	return base64.RawURLEncoding.EncodeToString(input)
}
