package hdwallet

import (
	"strings"
	"testing"

	txton "github.com/ranjbar-dev/hd-wallet/txproto/ton"
)

// TestTONLongCommentSnakeChaining and TestTONJettonLongForwardPayloadSnakeRef
// are structure-anchored, not vector-pinned: no authoritative TWC vector uses a
// comment/forward-payload longer than one cell (127 bytes), so the snake
// ref-chaining branches in tonSnakeCell (tx_ton.go ~190-204), the plain-comment
// path (tonCommentCell, ~182-188), and the jetton forward-payload Either=ref
// branch (tonBuildJettonBody, ~233-247) are otherwise never exercised by the
// existing byte-for-byte-pinned tests, which all use short comments. These
// tests instead build the cell tree directly and walk its refs/bits to confirm
// the snake chain reassembles to exactly the bytes that went in — the same
// self-consistency-round-trip convention used elsewhere in this repo for
// combinations with no authoritative vector (e.g. Solana durable-nonce +
// TokenTransfer).

// tonCollectSnakeBytes walks a byte-aligned cell chain linked by a single ref
// per cell (the shape tonSnakeCell produces) and concatenates every cell's data
// bytes in order, following refs[0] until a leaf is reached.
func tonCollectSnakeBytes(t *testing.T, c *tonCell) []byte {
	t.Helper()
	var out []byte
	for {
		if c.bitLen%8 != 0 {
			t.Fatalf("snake cell is not byte-aligned: bitLen=%d", c.bitLen)
		}
		out = append(out, c.bits[:c.bitLen/8]...)
		if len(c.refs) == 0 {
			return out
		}
		if len(c.refs) != 1 {
			t.Fatalf("snake cell has %d refs, want at most 1", len(c.refs))
		}
		c = c.refs[0]
	}
}

// TestTONLongCommentSnakeChaining builds a text comment well over the 127-byte
// single-cell budget and confirms tonCommentCell chains it across multiple ref
// cells and that the chain reassembles to the exact original comment bytes,
// with the leading 4-byte op=0 prefix intact.
func TestTONLongCommentSnakeChaining(t *testing.T) {
	// 300 ASCII bytes: cell 1 holds 127 bytes (4-byte op + 123 comment bytes),
	// cell 2 holds 127 comment bytes, cell 3 holds the remaining 50 — a 3-cell
	// chain, deliberately deeper than the minimal 2-cell case.
	comment := strings.Repeat("0123456789", 30) // 300 bytes
	if len(comment) != 300 {
		t.Fatalf("test setup: comment length = %d, want 300", len(comment))
	}

	root := tonCommentCell(comment)

	// Walk the chain depth to confirm real multi-cell chaining occurred, not an
	// accidental single inline cell.
	depth := 0
	for c := root; ; {
		if len(c.refs) == 0 {
			break
		}
		depth++
		c = c.refs[0]
	}
	if depth < 2 {
		t.Fatalf("expected a chain of at least 3 cells (depth>=2 refs), got depth=%d", depth)
	}

	got := tonCollectSnakeBytes(t, root)
	wantLen := 4 + len(comment)
	if len(got) != wantLen {
		t.Fatalf("reassembled length = %d, want %d", len(got), wantLen)
	}
	if got[0] != 0 || got[1] != 0 || got[2] != 0 || got[3] != 0 {
		t.Fatalf("op prefix = %v, want four zero bytes", got[:4])
	}
	if string(got[4:]) != comment {
		t.Fatalf("reassembled comment mismatch\n got: %q\nwant: %q", string(got[4:]), comment)
	}
}

// TestTONJettonLongForwardPayloadSnakeRef confirms that a jetton transfer whose
// comment is too long to fit inline in the transfer-body cell takes the
// Either=ref branch (tonBuildJettonBody, forward_payload) and that the
// ref-chained snake cell(s) reassemble to the exact original comment bytes.
func TestTONJettonLongForwardPayloadSnakeRef(t *testing.T) {
	longComment := strings.Repeat("the quick brown fox jumps over ", 7) // 224 bytes, forces the ref branch
	jt := &txton.JettonTransfer{
		QueryId:         69,
		JettonAmount:    1000 * 1000 * 1000,
		ToOwner:         "EQAFwMs5ha8OgZ9M4hQr80z9NkE7rGxUpE1hCFndiY6JnDx8",
		ResponseAddress: "EQBaKIMq5Am2p_rfR1IFTwsNWHxBkOpLTmwUain5Fj4llTXk",
		ForwardAmount:   1,
	}

	c, err := tonBuildJettonBody(jt, longComment)
	if err != nil {
		t.Fatalf("tonBuildJettonBody: %v", err)
	}

	if len(c.refs) == 0 {
		t.Fatalf("expected the long comment to force an Either=ref forward payload, but the body cell has no refs")
	}
	// The forward-payload ref is always appended last.
	payloadRoot := c.refs[len(c.refs)-1]

	got := tonCollectSnakeBytes(t, payloadRoot)
	wantLen := 4 + len(longComment)
	if len(got) != wantLen {
		t.Fatalf("reassembled forward-payload length = %d, want %d", len(got), wantLen)
	}
	if got[0] != 0 || got[1] != 0 || got[2] != 0 || got[3] != 0 {
		t.Fatalf("op prefix = %v, want four zero bytes", got[:4])
	}
	if string(got[4:]) != longComment {
		t.Fatalf("reassembled forward-payload comment mismatch\n got: %q\nwant: %q", string(got[4:]), longComment)
	}
}
