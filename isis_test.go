package isis_test

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/mdlayher/isis"
)

// diff compares two values of the same static type, returning a non-empty,
// human readable description of the difference when the values are not
// equal. Comparisons compare AreaAddress and netip.Addr by value, which cmp
// otherwise refuses for their unexported fields.
func diff[T any](tb testing.TB, want, got T) string {
	tb.Helper()

	return cmp.Diff(
		want, got,
		cmp.Comparer(func(x, y isis.AreaAddress) bool { return x == y }),
		cmp.Comparer(func(x, y netip.Addr) bool { return x == y }),
	)
}

// stringsOf renders each of vs with String, for comparison.
func stringsOf[T fmt.Stringer](vs []T) []string {
	out := make([]string, 0, len(vs))
	for _, v := range vs {
		out = append(out, v.String())
	}

	return out
}
