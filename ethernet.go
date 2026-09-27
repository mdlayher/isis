package isis

// An EthernetConfig configures an Ethernet transport. The zero value is
// usable: every field has a default or is optional.
type EthernetConfig struct {
	// Groups are the link layer multicast destinations to join on the
	// interface. A nil Groups joins AllISs, AllL1ISs, and AllL2ISs. A
	// non-nil empty Groups joins nothing.
	//
	// Whether an interface delivers IS-IS multicast without a membership
	// depends on its driver, not on IS-IS.
	Groups []SNPA
}
