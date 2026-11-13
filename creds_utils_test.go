package nkeys

import (
	"bytes"
	"strings"
	"testing"
)

// render builds a creds file from labeled blocks, inserting each payload
// between the matching canonical markers. Unknown labels keep their text so
// decoy/malformed markers can be exercised.
func render(blocks [][2]string) string {
	var sb strings.Builder
	for _, block := range blocks {
		label, payload := block[0], block[1]
		switch label {
		case "JWT":
			sb.WriteString(jwtBeginMarker + "\n" + payload + "\n" + jwtEndMarker + "\n")
		case "SEED":
			sb.WriteString(seedBeginMarker + "\n" + payload + "\n" + seedEndMarker + "\n")
		default:
			sb.WriteString(label + "\n")
			if payload != "" {
				sb.WriteString(payload + "\n")
			}
		}
	}
	return sb.String()
}

func Test_ParseDecoratedBareTextFailsClosed(t *testing.T) {
	// Undecorated input must never be accepted through a loose fallback.
	for _, contents := range [][]byte{
		[]byte("foo"),
		[]byte(credsJwt),
		[]byte(credsSeed),
		bytes.Join([][]byte{[]byte(credsJwt), []byte("\n"), []byte(credsSeed)}, nil),
	} {
		if _, err := ParseDecoratedJWT(contents); err == nil {
			t.Fatalf("expected ParseDecoratedJWT to reject %q", contents)
		}
		if _, err := ParseDecoratedNKey(contents); err == nil {
			t.Fatalf("expected ParseDecoratedNKey to reject %q", contents)
		}
		if _, err := ParseDecoratedUserNKey(contents); err == nil {
			t.Fatalf("expected ParseDecoratedUserNKey to reject %q", contents)
		}
	}
}

func Test_ParseDecoratedDuplicateBlocksFail(t *testing.T) {
	dupeJWT := render([][2]string{
		{"JWT", credsJwt},
		{"JWT", credsJwt},
		{"SEED", credsSeed},
	})
	if _, err := ParseDecoratedJWT([]byte(dupeJWT)); err == nil {
		t.Fatal("expected duplicate JWT block to be rejected")
	}

	dupeSeed := render([][2]string{
		{"JWT", credsJwt},
		{"SEED", credsSeed},
		{"SEED", credsSeed},
	})
	for _, parse := range []func([]byte) (KeyPair, error){ParseDecoratedNKey, ParseDecoratedUserNKey} {
		if _, err := ParseDecoratedJWT([]byte(dupeSeed)); err == nil {
			t.Fatal("expected duplicate seed block to be rejected")
		}
		if _, err := parse([]byte(dupeSeed)); err == nil {
			t.Fatal("expected duplicate seed block to be rejected")
		}
	}
}

func Test_ParseDecoratedDecoyAndUnknownBlocksFail(t *testing.T) {
	// A decoy JWT-looking block placed before the real one.
	decoyFirst := render([][2]string{
		{"-----BEGIN NATS ACCOUNT JWT-----", ""},
		{"eyJhbGciOiJlZDI1NTE5In0.decoy.sig", ""},
		{"------END NATS ACCOUNT JWT------", ""},
		{"JWT", credsJwt},
		{"SEED", credsSeed},
	})
	for _, contents := range [][]byte{[]byte(decoyFirst)} {
		if _, err := ParseDecoratedJWT(contents); err == nil {
			t.Fatal("expected decoy block to be rejected")
		}
		if _, err := ParseDecoratedNKey(contents); err == nil {
			t.Fatal("expected decoy block to be rejected")
		}
	}

	// Extra unknown decorated block after the valid pair.
	extraBlock := render([][2]string{
		{"JWT", credsJwt},
		{"SEED", credsSeed},
		{"-----BEGIN NATS SERVER JWT-----", ""},
		{"eyJhbGciOiJlZDI1NTE5In0.server.sig", ""},
		{"------END NATS SERVER JWT------", ""},
	})
	if _, err := ParseDecoratedJWT([]byte(extraBlock)); err == nil {
		t.Fatal("expected residual unknown block to be rejected")
	}
}

func Test_ParseDecoratedInterleavedBlocksFail(t *testing.T) {
	interleaved := "-----BEGIN NATS USER JWT-----\n" +
		credsJwt + "\n" +
		"-----BEGIN USER NKEY SEED-----\n" +
		credsSeed + "\n" +
		"------END USER NKEY SEED------\n" +
		"------END NATS USER JWT------\n"
	if _, err := ParseDecoratedJWT([]byte(interleaved)); err == nil {
		t.Fatal("expected interleaved blocks to be rejected")
	}
	if _, err := ParseDecoratedUserNKey([]byte(interleaved)); err == nil {
		t.Fatal("expected interleaved blocks to be rejected")
	}

	// Unterminated block.
	unterminated := jwtBeginMarker + "\n" + credsJwt + "\n"
	if _, err := ParseDecoratedJWT([]byte(unterminated)); err == nil {
		t.Fatal("expected unterminated block to be rejected")
	}

	// End marker without a matching begin.
	dangling := jwtEndMarker + "\n" + credsJwt + "\n"
	if _, err := ParseDecoratedJWT([]byte(dangling)); err == nil {
		t.Fatal("expected dangling end marker to be rejected")
	}
}

func Test_ParseDecoratedWrongSeedTypeFails(t *testing.T) {
	accountSeed := "SOAOTBNEUHZDFJT3EUMELT7MQTP24JF3XVCXQNDSCU74G5IU6VAJBKH5LI"
	wrongType := render([][2]string{
		{"JWT", credsJwt},
		{"SEED", accountSeed},
	})
	if _, err := ParseDecoratedUserNKey([]byte(wrongType)); err == nil {
		t.Fatal("expected non-user seed to be rejected")
	} else if err != ErrInvalidUserSeed {
		t.Fatalf("expected ErrInvalidUserSeed, got %v", err)
	}
}

func Test_ParseDecoratedMissingBlocksFail(t *testing.T) {
	jwtOnly := render([][2]string{{"JWT", credsJwt}})
	if _, err := ParseDecoratedNKey([]byte(jwtOnly)); err == nil {
		t.Fatal("expected seed-only parse of JWT-only file to fail")
	}

	seedOnly := render([][2]string{{"SEED", credsSeed}})
	if _, err := ParseDecoratedJWT([]byte(seedOnly)); err == nil {
		t.Fatal("expected JWT parse of seed-only file to fail")
	}
}

func Test_ParseDecoratedMalformedPayloadsFail(t *testing.T) {
	// Multi-line block payloads are rejected.
	multiLine := "-----BEGIN NATS USER JWT-----\nline1\nline2\n------END NATS USER JWT------\n" +
		"-----BEGIN USER NKEY SEED-----\n" + credsSeed + "\n------END USER NKEY SEED------\n"
	if _, err := ParseDecoratedJWT([]byte(multiLine)); err == nil {
		t.Fatal("expected multi-line block payload to be rejected")
	}

	// Empty block payload is rejected.
	emptyBlock := "-----BEGIN USER NKEY SEED-----\n\n------END USER NKEY SEED------\n"
	if _, err := ParseDecoratedUserNKey([]byte(emptyBlock)); err == nil {
		t.Fatal("expected empty seed block to be rejected")
	}

	// A correctly labeled block with garbage seed content fails closed.
	garbageSeed := render([][2]string{
		{"JWT", credsJwt},
		{"SEED", "SUnot-a-valid-seed!!!"},
	})
	if _, err := ParseDecoratedUserNKey([]byte(garbageSeed)); err == nil {
		t.Fatal("expected malformed seed payload to be rejected")
	}
}

func Test_ParseDecoratedDoesNotRetainSecretCopies(t *testing.T) {
	contents := []byte(decoratedCreds)

	jwt, seed, err := parseDecorated(contents)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(seed, []byte(credsSeed)) {
		t.Fatal("parseDecorated did not return the expected seed")
	}
	if !bytes.Equal(jwt, []byte(credsJwt)) {
		t.Fatal("parseDecorated did not return the expected JWT")
	}

	kp, err := FromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}

	// The caller wipes its temporary copy; the key pair keeps its own.
	wipe(seed)
	if !bytes.Equal(seed, make([]byte, len(credsSeed))) {
		t.Fatal("wipe did not clear the temporary seed copy")
	}
	kp2, err := ParseDecoratedNKey(contents)
	if err != nil {
		t.Fatal(err)
	}
	pub1, err := kp.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	pub2, err := kp2.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if pub1 != pub2 {
		t.Fatal("both parsers should derive the same key pair")
	}

	// A JWT-only parse must not leave seed material behind either.
	jwtStr, err := ParseDecoratedJWT(contents)
	if err != nil {
		t.Fatal(err)
	}
	if jwtStr != credsJwt {
		t.Fatal("JWT mismatch after seed-bearing parse")
	}
}

const (
	credsSeed      = `SUAOTBNEUHZDFJT3EUMELT7MQTP24JF3XVCXQNDSCU74G5IU6VAJBKH5LI`
	credsJwt       = `eyJ0eXAiOiJqd3QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ.eyJqdGkiOiJHVDROVU5NRUY3Wk1XQ1JCWFZWVURLUVQ2WllQWjc3VzRKUlFYRDNMMjRIS1VKRUNRSDdRIiwiaWF0IjoxNTkwNzgxNTkzLCJpc3MiOiJBQURXTFRISUNWNFNVQUdGNkVLTlZFVzVCQlA3WVJESUJHV0dHSFo1SkJET1FZQTdHVUZNNkFRVSIsIm5hbWUiOiJPUEVSQVRPUiIsInN1YiI6IlVERTZXVEdMVFRQQ1JKUkpDS0JKUkdWTlpUTElWUjdMRUVFTFI0Q1lXV1dCS0pTN1hZSUtYRFVVIiwibmF0cyI6eyJwdWIiOnt9LCJzdWIiOnt9LCJ0eXBlIjoidXNlciIsInZlcnNpb24iOjJ9fQ.c_XQT04wEoVVNDRjPHeKwe17BOrSpQTcftwIbB7KoNEIz6peZCJDc4-J3emVepHofUOWy7IAo9TlLwYhuGHWAQ`
	decoratedCreds = `-----BEGIN NATS USER JWT-----
eyJ0eXAiOiJqd3QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ.eyJqdGkiOiJHVDROVU5NRUY3Wk1XQ1JCWFZWVURLUVQ2WllQWjc3VzRKUlFYRDNMMjRIS1VKRUNRSDdRIiwiaWF0IjoxNTkwNzgxNTkzLCJpc3MiOiJBQURXTFRISUNWNFNVQUdGNkVLTlZFVzVCQlA3WVJESUJHV0dHSFo1SkJET1FZQTdHVUZNNkFRVSIsIm5hbWUiOiJPUEVSQVRPUiIsInN1YiI6IlVERTZXVEdMVFRQQ1JKUkpDS0JKUkdWTlpUTElWUjdMRUVFTFI0Q1lXV1dCS0pTN1hZSUtYRFVVIiwibmF0cyI6eyJwdWIiOnt9LCJzdWIiOnt9LCJ0eXBlIjoidXNlciIsInZlcnNpb24iOjJ9fQ.c_XQT04wEoVVNDRjPHeKwe17BOrSpQTcftwIbB7KoNEIz6peZCJDc4-J3emVepHofUOWy7IAo9TlLwYhuGHWAQ
------END NATS USER JWT------

************************* IMPORTANT *************************
NKEY Seed printed below can be used to sign and prove identity.
NKEYs are sensitive and should be treated as secrets.

-----BEGIN USER NKEY SEED-----
SUAOTBNEUHZDFJT3EUMELT7MQTP24JF3XVCXQNDSCU74G5IU6VAJBKH5LI
------END USER NKEY SEED------

*************************************************************
`
)

func Test_ParseDecoratedSeedAndJWT(t *testing.T) {
	// test with and without \r\n
	for _, creds := range [][]byte{[]byte(decoratedCreds),
		bytes.ReplaceAll([]byte(decoratedCreds), []byte{'\n'}, []byte{'\r', '\n'})} {
		kp, err := ParseDecoratedUserNKey(creds)
		if err != nil {
			t.Fatal(err)
		}
		pu, err := kp.Seed()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(pu, []byte(credsSeed)) {
			t.Fatal("seeds don't match")
		}

		kp, err = ParseDecoratedNKey(creds)
		if err != nil {
			t.Fatal(err)
		}
		pu, err = kp.Seed()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(pu, []byte(credsSeed)) {
			t.Fatal("seeds don't match")
		}

		jwt, err := ParseDecoratedJWT(creds)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal([]byte(jwt), []byte(credsJwt)) {
			t.Fatal("jwt don't match")
		}
	}
}
