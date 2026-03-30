package gpo

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"unicode/utf16"
	"unicode/utf8"
)

// Fetch runs gpresult /X to produce a full RSoP XML report and returns the
// content as a UTF-8 encoded byte slice.
//
// Requires elevation to include computer-configuration data.  If gpresult
// exits with a non-zero code the raw output is included in the error message
// so the caller can surface it in the UI.
func Fetch() ([]byte, error) {
	tmpFile := filepath.Join(os.TempDir(), "gpoview_rsop.xml")
	// Best-effort cleanup; ignore error.
	defer os.Remove(tmpFile)

	// /F  – force overwrite of any existing file.
	cmd := exec.Command("gpresult", "/X", tmpFile, "/F")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("gpresult failed (%w). Output:\n%s", err, string(out))
	}

	raw, err := os.ReadFile(tmpFile)
	if err != nil {
		return nil, fmt.Errorf("reading gpresult output: %w", err)
	}

	utf8data, err := toUTF8(raw)
	if err != nil {
		return nil, fmt.Errorf("decoding gpresult XML encoding: %w", err)
	}

	// After UTF-16→UTF-8 conversion the XML prolog still declares
	// encoding="utf-16".  Go's xml.Decoder honours that declaration and errors
	// out because no CharsetReader is configured.  Rewrite the declaration to
	// encoding="utf-8" so the decoder accepts it.
	utf8data = fixXMLEncoding(utf8data)

	return utf8data, nil
}

// fixXMLEncoding replaces the encoding attribute value in the XML prolog with
// "utf-8".  It operates on bytes so it works before any XML parsing.
func fixXMLEncoding(b []byte) []byte {
	// We only need to look at the first ~100 bytes, where the prolog lives.
	const maxSearch = 200
	search := b
	if len(search) > maxSearch {
		search = b[:maxSearch]
	}

	lower := bytes.ToLower(search)
	idx := bytes.Index(lower, []byte(`encoding="`))
	if idx == -1 {
		idx = bytes.Index(lower, []byte(`encoding='`))
		if idx == -1 {
			return b
		}
	}

	// Find the closing quote.
	start := idx + len(`encoding="`)
	quote := b[start-1]
	end := bytes.IndexByte(b[start:], quote)
	if end == -1 {
		return b
	}
	end += start

	// Replace whatever is between the quotes with "utf-8".
	result := make([]byte, 0, len(b))
	result = append(result, b[:start]...)
	result = append(result, []byte("utf-8")...)
	result = append(result, b[end:]...)
	return result
}

// toUTF8 converts UTF-16 LE or BE (detected via BOM) to UTF-8.
// If no BOM is present the bytes are returned unchanged (assumed UTF-8).
func toUTF8(b []byte) ([]byte, error) {
	if len(b) < 2 {
		return b, nil
	}

	var order binary.ByteOrder
	switch {
	case b[0] == 0xFF && b[1] == 0xFE:
		order = binary.LittleEndian
		b = b[2:]
	case b[0] == 0xFE && b[1] == 0xFF:
		order = binary.BigEndian
		b = b[2:]
	default:
		return b, nil // already UTF-8
	}

	// Ensure even length.
	if len(b)%2 != 0 {
		b = append(b, 0)
	}

	u16s := make([]uint16, len(b)/2)
	for i := range u16s {
		u16s[i] = order.Uint16(b[i*2:])
	}

	runes := utf16.Decode(u16s)

	result := make([]byte, 0, len(runes)*3)
	var buf [utf8.UTFMax]byte
	for _, r := range runes {
		n := utf8.EncodeRune(buf[:], r)
		result = append(result, buf[:n]...)
	}

	return result, nil
}
