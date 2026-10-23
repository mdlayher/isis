//go:build interop && linux

// Package interop tests github.com/mdlayher/isis against a real IS-IS
// implementation: FRRouting's isisd, the suite's oracle, hosted as native
// daemons in unprivileged network namespaces by
// github.com/mdlayher/frrtest. The oracle needs Linux, iproute2 on $PATH,
// and zebra and isisd from exactly FRR frrVersion, since isisd learns its
// interfaces through zebra. The repository's nix dev shell provides all
// of it:
//
//	nix develop -c go test -tags interop -race ./interop
//
// $ISIS_INTEROP_FRR names the daemon directory explicitly, such as
// /usr/lib/frr or a Nix store path's libexec/frr. Without it, the harness
// looks in the usual install locations and beside vtysh on $PATH.
//
// A missing oracle is a hard failure, never a skip: the interop build tag
// is itself the explicit opt-in, and a green run which tested nothing
// would be worse than a red one.
//
// When $ISIS_INTEROP_LOGDIR is set, each FRR instance's logs are saved
// there on teardown, and a failed test also logs them.
package interop

import "testing"

func TestMain(m *testing.M) { oracle.Main(m) }
