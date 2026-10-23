//go:build interop && !linux

package interop

import (
	"log"
	"testing"
)

func TestMain(_ *testing.M) {
	// A hard failure, never a skip, and never a green run of zero tests:
	// the FRR oracle runs in network namespaces, which need Linux. See
	// the package documentation in main_test.go.
	log.Fatal("interop: this suite requires Linux to host the FRR oracle in network namespaces")
}
