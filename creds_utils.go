package nkeys

import (
	"bytes"
	"fmt"
)

// Canonical block markers used by decorated .creds files. Only these exact
// labels are accepted; anything else makes the file invalid.
const (
	jwtBeginMarker  = "-----BEGIN NATS USER JWT-----"
	jwtEndMarker    = "------END NATS USER JWT------"
	seedBeginMarker = "-----BEGIN USER NKEY SEED-----"
	seedEndMarker   = "------END USER NKEY SEED------"
)

var (
	endMarkerFor = map[string]string{
		jwtBeginMarker:  jwtEndMarker,
		seedBeginMarker: seedEndMarker,
	}
	userSeedPrefix = []byte("SU")
)

// markerLine returns the canonical marker carried by a line, or an empty
// string when the line is not an exact block marker. A line that merely looks
// marker-like (dashes with an unknown or malformed label) is rejected by the
// caller instead of being ignored.
func markerLine(line []byte) string {
	for _, marker := range []string{jwtBeginMarker, jwtEndMarker, seedBeginMarker, seedEndMarker} {
		if string(line) == marker {
			return marker
		}
	}
	return ""
}

// looksLikeMarker reports whether a line uses the decorated block-marker
// convention without matching one of the four canonical markers.
func looksLikeMarker(line []byte) bool {
	trimmed := bytes.TrimSpace(line)
	return len(trimmed) >= 7 &&
		bytes.HasPrefix(trimmed, []byte("-----")) &&
		bytes.HasSuffix(trimmed, []byte("-----"))
}

// parseDecorated scans a .creds file and accepts only the well-defined layout:
// exactly one "NATS USER JWT" block and exactly one "USER NKEY SEED" block,
// each carrying a single payload line. Decoy blocks, duplicated markers,
// interleaved blocks, wrong block types and any other decorated block cause a
// fail-closed error. Plain prose outside of blocks (e.g. the standard warning
// banner) is ignored; an undecorated payload is never treated as a fallback.
//
// The returned seed is a freshly allocated copy. Callers must wipe it once the
// key pair has been derived so no extra copy of the secret is retained.
func parseDecorated(contents []byte) (jwt []byte, seed []byte, err error) {
	lines := bytes.Split(contents, []byte("\n"))

	var (
		openMarker string
		block      [][]byte
		seenJWT    bool
		seenSeed   bool
	)

	closeBlock := func() error {
		if len(block) != 1 {
			return fmt.Errorf("%w: block payload must be a single non-empty line", ErrInvalidCredentials)
		}
		payload := block[0]
		if len(bytes.TrimSpace(payload)) == 0 || bytes.ContainsAny(payload, " \t") {
			return fmt.Errorf("%w: block payload is malformed", ErrInvalidCredentials)
		}
		switch openMarker {
		case jwtBeginMarker:
			if seenJWT {
				return fmt.Errorf("%w: duplicated user JWT block", ErrInvalidCredentials)
			}
			seenJWT = true
			jwt = append([]byte(nil), payload...)
		case seedBeginMarker:
			if seenSeed {
				return fmt.Errorf("%w: duplicated user nkey seed block", ErrInvalidCredentials)
			}
			seenSeed = true
			seed = append([]byte(nil), payload...)
		}
		openMarker = ""
		block = nil
		return nil
	}

	for _, raw := range lines {
		line := bytes.TrimSuffix(raw, []byte("\r"))

		if marker := markerLine(line); marker != "" {
			if openMarker != "" {
				if marker == endMarkerFor[openMarker] {
					if cerr := closeBlock(); cerr != nil {
						return nil, nil, cerr
					}
					continue
				}
				return nil, nil, fmt.Errorf("%w: nested or interleaved block marker %q", ErrInvalidCredentials, marker)
			}
			if _, isBegin := endMarkerFor[marker]; !isBegin {
				return nil, nil, fmt.Errorf("%w: unexpected end marker %q", ErrInvalidCredentials, marker)
			}
			openMarker = marker
			continue
		}

		if openMarker != "" {
			block = append(block, line)
			continue
		}

		if looksLikeMarker(line) {
			return nil, nil, fmt.Errorf("%w: unknown block marker %q", ErrInvalidCredentials, string(line))
		}
		// Non-decorated prose (banner, blank lines) outside of blocks is
		// allowed so the standard creds layout keeps working.
	}

	if openMarker != "" {
		return nil, nil, fmt.Errorf("%w: unterminated block %q", ErrInvalidCredentials, openMarker)
	}
	if !seenJWT || !seenSeed {
		return nil, nil, fmt.Errorf("%w: expected one user JWT block and one user nkey seed block", ErrInvalidCredentials)
	}
	return jwt, seed, nil
}

// ParseDecoratedJWT takes a creds file and returns the JWT portion.
func ParseDecoratedJWT(contents []byte) (string, error) {
	jwt, seed, err := parseDecorated(contents)
	if err != nil {
		return "", err
	}
	wipe(seed)
	return string(jwt), nil
}

// ParseDecoratedNKey takes a creds file, finds the NKey portion and creates a
// key pair from it.
func ParseDecoratedNKey(contents []byte) (KeyPair, error) {
	_, seed, err := parseDecorated(contents)
	if err != nil {
		return nil, err
	}
	defer wipe(seed)

	if !bytes.HasPrefix(seed, userSeedPrefix) {
		return nil, ErrInvalidNkeySeed
	}
	return FromSeed(seed)
}

// ParseDecoratedUserNKey takes a creds file, finds the NKey portion and creates a
// key pair from it. Similar to ParseDecoratedNKey but fails for non-user keys.
func ParseDecoratedUserNKey(contents []byte) (KeyPair, error) {
	_, seed, err := parseDecorated(contents)
	if err != nil {
		return nil, err
	}
	defer wipe(seed)

	if !bytes.HasPrefix(seed, userSeedPrefix) {
		return nil, ErrInvalidUserSeed
	}
	return FromSeed(seed)
}

// wipe overwrites a secret buffer so no extra copy of the material is kept in
// memory once parsing is finished.
func wipe(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
}
