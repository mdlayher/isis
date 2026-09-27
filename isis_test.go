package isis

import (
	"net/netip"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// diff compares two values of the same static type, returning a non-empty,
// human readable description of the difference when the values are not
// equal. Comparisons read AreaAddress's unexported fields and compare
// netip.Addr by value, which cmp otherwise refuses.
func diff[T any](tb testing.TB, want, got T) string {
	tb.Helper()

	return cmp.Diff(
		want, got,
		cmp.AllowUnexported(AreaAddress{}),
		cmp.Comparer(func(x, y netip.Addr) bool { return x == y }),
	)
}
