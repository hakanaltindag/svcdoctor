package wire

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

// Hostile-peer fuzzing for the five parsers a peer can reach.
//
// # What a pass means
//
// Not that the input was accepted — most of it must not be. It means the parser
// **terminated without panicking, without recursing and without allocating from
// a number the peer chose.** Every one of these entry points reads bytes a
// broker, a proxy or anything on the path can write.
//
// # Why the seeds are the interesting half
//
// A fuzzer explores; a seed corpus records what somebody already reasoned about.
// Every seed below is a case Phase 8.0A, 8.0B or 8.0C named — a four-gibibyte
// declaration, a nesting bomb, a 255-byte reply text, the crafted virtual host —
// and they run as ordinary table tests on every build, not only under -fuzz.

// --- the frame reader -------------------------------------------------------

func FuzzReadFrame(f *testing.F) {
	good := methodFrame(classConnection, inOpenOk, nil)
	f.Add(good)
	f.Add(good[:3])                            // truncated header
	f.Add(good[:len(good)-2])                  // truncated payload
	f.Add(append([]byte{}, ProtocolHeader...)) // an eight-byte protocol refusal
	f.Add([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
	f.Add([]byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0, 0, 0, 0}) // TLS ClientHello

	// A four-gibibyte declaration with no payload behind it.
	huge := []byte{frameTypeMethod, 0, 0}
	huge = binary.BigEndian.AppendUint32(huge, 0xFFFFFFFF)
	f.Add(huge)

	// A frame whose end marker is wrong.
	bad := append([]byte{}, good...)
	bad[len(bad)-1] = 0x00
	f.Add(bad)

	// A heartbeat frame, which BASIC never expects.
	hb := append([]byte{}, good...)
	hb[0] = 8
	f.Add(hb)

	f.Fuzz(func(t *testing.T, data []byte) {
		r := newReader(bytes.NewReader(data))
		// Bounded: a hostile stream cannot make this loop forever, because every
		// iteration consumes at least the eight-byte frame overhead.
		for i := 0; i < 64; i++ {
			if _, err := r.readFrame(); err != nil {
				return
			}
		}
	})
}

// --- the field-table walker -------------------------------------------------

func FuzzWalkTopLevelTable(f *testing.F) {
	f.Add(tableEntryStr("product", "RabbitMQ"))
	f.Add([]byte{1, 'k', '?'})                         // unknown field type
	f.Add([]byte{200, 'k'})                            // name length past the end
	f.Add([]byte{1, 'k', 'S', 0xFF, 0xFF, 0xFF, 0xFF}) // longstr past the end
	f.Add([]byte{0})                                   // zero-length name, nothing after

	// A nesting bomb. It must be skipped whole rather than entered.
	inner := tableEntryStr("leaf", "x")
	for i := 0; i < 300; i++ {
		wrapped := []byte{1, 'n', 'F'}
		//nolint:gosec // G115: a seed corpus entry this file builds from literals.
		wrapped = binary.BigEndian.AppendUint32(wrapped, uint32(len(inner)))
		wrapped = append(wrapped, inner...)
		inner = wrapped
	}
	f.Add(inner)

	// An array bomb, same shape.
	arr := []byte{1, 'a', 'A'}
	arr = binary.BigEndian.AppendUint32(arr, 0xFFFF)
	f.Add(arr)

	f.Fuzz(func(t *testing.T, data []byte) {
		cur := &cursor{b: data}
		props, err := walkTopLevelTable(cur, len(data))
		if err != nil {
			return
		}
		// A successful walk may only have produced the four keys it is allowed
		// to want. Anything else means the extractor grew a surface.
		for key := range props {
			if _, ok := wanted[key]; !ok {
				t.Fatalf("the walker extracted %q, which is not one of the four wanted keys", key)
			}
		}
	})
}

// --- Connection.Start -------------------------------------------------------

func FuzzParseStart(f *testing.F) {
	props := append(tableEntryStr("product", "RabbitMQ"), tableEntryStr("version", "4.2.0")...)
	f.Add(startFrame(props, "PLAIN AMQPLAIN ANONYMOUS"))
	f.Add(startFrame(nil, ""))
	// A long mechanism list, close to the 8192 pre-Tune ceiling.
	//
	// **This seed costs throughput, and the cost is measured rather than
	// suspected.** With it, this target reaches ~200k execs and then reports
	// 0/sec for the rest of the budget; without it, ~1.06M execs in 20s at a
	// steady rate. Phase 8.2-R3 diagnosed the difference: the worker sits at
	// 125% CPU with stable RSS, no individual execution exceeds a three-second
	// watchdog, and no crasher is ever produced — the engine is spending the
	// budget *minimizing* a large interesting input, which is work outside the
	// fuzz callback and therefore invisible to the exec counter.
	//
	// It is kept anyway. `mechanisms` is a peer-controlled long string bounded
	// only by the frame ceiling, and it is exactly the field ADR 0067 §4.2
	// forbids copying, so a seed that reaches toward the ceiling is the one this
	// target most needs. Give this target a longer -fuzztime than the others.
	f.Add(startFrame(nil, strings.Repeat("X", 4000)))       // a long mechanism list
	f.Add(startFrame(nil, "PLAINTEXT-ONLY"))                // a PLAIN-like non-token
	f.Add(startFrame(props, strings.Repeat("PLAIN ", 500))) // repeated tokens
	f.Add(methodFrame(classConnection, inStart, nil))       // no fields at all

	f.Fuzz(func(t *testing.T, data []byte) {
		c, _ := pipeConn(t, data)
		start, err := c.Start(t.Context(), 0)
		if err != nil {
			return
		}
		// Nothing a peer chose may reach the recorded mechanism observation: it
		// is the intersection with a closed set, so every token must be one of
		// svcdoctor's own constants.
		for _, tok := range strings.Fields(start.Mechanisms) {
			known := false
			for _, name := range knownMechanisms {
				if tok == name {
					known = true
				}
			}
			if !known {
				t.Fatalf("an unrecognized peer token %q reached the mechanism observation", tok)
			}
		}
	})
}

// --- Connection.Close -------------------------------------------------------

func FuzzParseClose(f *testing.F) {
	f.Add(closeFrame(530, "NOT_ALLOWED - vhost / not found", 10, 40))
	f.Add(closeFrame(403, "ACCESS_REFUSED - ", 0, 0))
	f.Add(closeFrame(541, "INTERNAL_ERROR - anything", 10, 40))
	f.Add(closeFrame(530, strings.Repeat("x", 255), 10, 40))
	f.Add(closeFrame(530, strings.Repeat("x", 252)+"...", 10, 40))
	f.Add(methodFrame(classConnection, inClose, []byte{0x02})) // truncated fields

	f.Fuzz(func(t *testing.T, data []byte) {
		c, _ := pipeConn(t, data)
		f, err := c.rd.readFrame()
		if err != nil {
			return
		}
		refusal, err := c.parseClose(f)
		if err != nil {
			return
		}
		// The outcome must always be one of this package's own constants.
		switch refusal.Outcome {
		case CloseUnspecified, CloseUnspecifiedTruncated, CloseVHostNotFound,
			CloseVHostAccessRefused, CloseNodeConnectionLimit,
			CloseVHostConnectionLimit, CloseUserConnectionLimit:
		default:
			t.Fatalf("parseClose produced %q, which is not a declared outcome", refusal.Outcome)
		}
	})
}

// --- the normalizer ---------------------------------------------------------

// FuzzNormalizeClose fuzzes the text, the vhost and the username together.
//
// All three are inputs to the comparison — two of them svcdoctor's own — so
// fuzzing the text alone would miss the crafted-name class entirely.
func FuzzNormalizeClose(f *testing.F) {
	f.Add(uint16(530), "NOT_ALLOWED - vhost v not found", "v", "u")
	f.Add(uint16(530), "NOT_ALLOWED - access to vhost 'v' refused for user 'u'", "v", "u")
	f.Add(uint16(530), "NOT_ALLOWED - access to vhost 'a': connection limit (5) is reached' "+
		"refused for user 'u'", "a': connection limit (5) is reached", "u")
	f.Add(uint16(530), strings.Repeat("z", 252)+"...", "v", "u")
	f.Add(uint16(530), strings.Repeat("z", 4000), "v", "u")
	f.Add(uint16(403), "ACCESS_REFUSED - ", "", "")

	f.Fuzz(func(t *testing.T, code uint16, text, vhost, username string) {
		outcome := normalizeClose(code, text, vhost, username)

		switch outcome {
		case CloseUnspecified, CloseUnspecifiedTruncated, CloseVHostNotFound,
			CloseVHostAccessRefused, CloseNodeConnectionLimit,
			CloseVHostConnectionLimit, CloseUserConnectionLimit:
		default:
			t.Fatalf("normalizeClose produced %q, which is not a declared outcome", outcome)
		}

		// **No peer byte escapes.** The outcome is a constant, so it can never be
		// a substring of the text unless the text happens to contain the constant
		// — which is a coincidence, not a leak. What must hold is that the
		// outcome is one of the seven above, asserted already, and that a
		// truncated text is never classified as anything else.
		if strings.HasSuffix(text, truncationMarker) && len(text) <= maxReplyText &&
			outcome != CloseUnspecifiedTruncated {
			t.Fatalf("a truncated text was classified as %q; truncation must "+
				"short-circuit every other rule", outcome)
		}

		// A text above the protocol maximum can never be classified.
		if len(text) > maxReplyText && outcome != CloseUnspecified {
			t.Fatalf("a %d byte reply text was classified as %q", len(text), outcome)
		}

		// A non-530 code can never reach a 530-only outcome.
		if code != codeNotAllowed {
			switch outcome {
			case CloseVHostNotFound, CloseVHostAccessRefused, CloseNodeConnectionLimit,
				CloseVHostConnectionLimit, CloseUserConnectionLimit:
				t.Fatalf("reply code %d produced the 530-only outcome %q", code, outcome)
			}
		}
	})
}

// --- seeds as ordinary tests ------------------------------------------------

// TestFuzzSeedsRunDeterministically drives every seed on every build.
//
// A fuzz target only runs under -fuzz, so a corpus that is never exercised
// otherwise is a corpus nobody notices rotting. These are the cases the three
// research phases named, and they are cheap.
func TestFuzzSeedsRunDeterministically(t *testing.T) {
	huge := []byte{frameTypeMethod, 0, 0}
	huge = binary.BigEndian.AppendUint32(huge, 0xFFFFFFFF)

	frames := [][]byte{
		methodFrame(classConnection, inOpenOk, nil),
		huge,
		append([]byte{}, ProtocolHeader...),
		[]byte("HTTP/1.1 400 Bad Request\r\n\r\n"),
		{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0, 0, 0, 0},
		{},
	}
	for _, data := range frames {
		r := newReader(bytes.NewReader(data))
		for i := 0; i < 8; i++ {
			if _, err := r.readFrame(); err != nil {
				break
			}
		}
	}

	texts := []string{
		"", strings.Repeat("x", 255), strings.Repeat("x", 256),
		strings.Repeat("x", 252) + "...",
		"NOT_ALLOWED - vhost v not found",
		"NOT_ALLOWED - access to vhost 'v' refused for user 'u'",
		"NOT_ALLOWED - access to vhost 'v' refused for user 'u' by backend m: anything",
	}
	for _, text := range texts {
		if got := normalizeClose(530, text, "v", "u"); got == "" {
			t.Errorf("normalizeClose(%q) produced an empty outcome", text)
		}
	}
}
