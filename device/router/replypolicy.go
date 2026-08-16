package router

import "github.com/kabili207/meshcore-go/core/codec"

// ReplyScope selects the transport scope a flooded reply is sent with.
// Ported from the firmware's RoutingPolicy.h (v1.17).
type ReplyScope uint8

const (
	// ReplyScopeRequest reuses the scope the request arrived on.
	ReplyScopeRequest ReplyScope = iota
	// ReplyScopeDefault falls back to this node's default region scope.
	ReplyScopeDefault
	// ReplyScopeNone sends un-scoped (RouteTypeFlood).
	ReplyScopeNone
)

func (s ReplyScope) String() string {
	switch s {
	case ReplyScopeRequest:
		return "request"
	case ReplyScopeDefault:
		return "default"
	case ReplyScopeNone:
		return "none"
	}
	return "unknown"
}

// ChooseReplyScope decides how to scope a flooded reply.
//
// The case that motivated this upstream: a reply sent un-scoped is dropped at
// hop 0 by any repeater running flood.max.unscoped=0. So when the request's
// scope cannot be resolved, falling back to a configured default beats sending
// un-scoped. The exception is a requester that deliberately flooded un-scoped,
// which is mirrored rather than overridden.
//
// Mirrors firmware's chooseReplyScope.
func ChooseReplyScope(requestScopeKnown, requestWasUnscopedFlood, defaultScopeKnown bool) ReplyScope {
	if requestScopeKnown {
		return ReplyScopeRequest
	}
	if requestWasUnscopedFlood {
		return ReplyScopeNone // requester chose un-scoped, so mirror it
	}
	if defaultScopeKnown {
		// Scope unknowable: the request came in DIRECT (no transport codes), or
		// its code matched no configured region.
		return ReplyScopeDefault
	}
	return ReplyScopeNone
}

// ResolveReplyScope picks the transport key for a flooded reply to origPkt,
// applying ChooseReplyScope against this router's region map and configured
// scopes. A null return means send un-scoped.
//
// origPkt may be nil (no originating packet, e.g. an unsolicited send), which
// is treated as "scope unknowable" and so uses the default scope when set.
func (r *Router) ResolveReplyScope(origPkt *codec.Packet) TransportKey {
	var requestScope TransportKey
	requestScopeKnown := false
	requestWasUnscopedFlood := false

	if origPkt != nil {
		switch origPkt.RouteType() {
		case codec.RouteTypeTransportFlood:
			// Resolve the code back to a region we hold a key for. The code is
			// an HMAC over the request's own payload, so this must be done
			// against the original packet. A code matching no region leaves the
			// scope unknown, as firmware leaves recv_pkt_region NULL.
			if key, ok := r.matchScopeKey(origPkt); ok {
				requestScope = key
				requestScopeKnown = true
			}
		case codec.RouteTypeFlood:
			requestWasUnscopedFlood = true
		}
	}

	defaultScope := r.cfg.DefaultReplyScope
	if defaultScope.IsNull() {
		// Fall back to the send scope, so a node configured with only SendScope
		// keeps its previous behavior.
		defaultScope = r.cfg.SendScope
	}

	switch ChooseReplyScope(requestScopeKnown, requestWasUnscopedFlood, !defaultScope.IsNull()) {
	case ReplyScopeRequest:
		return requestScope
	case ReplyScopeDefault:
		return defaultScope
	default:
		return TransportKey{}
	}
}

// matchScopeKey returns the transport key of the first region whose code
// matches the packet's transport_codes[0]. Unlike FindMatch, which answers
// "may this be forwarded", this answers "which key was it sent with", so it
// applies no flag mask: a region that denies forwarding is still the region the
// request arrived on, and a reply to it belongs in the same scope.
func (r *Router) matchScopeKey(pkt *codec.Packet) (TransportKey, bool) {
	rm := r.cfg.RegionMap
	if rm == nil {
		return TransportKey{}, false
	}

	for i := range rm.Count() {
		region := rm.ByIndex(i)

		var keys []TransportKey
		if len(region.Name) > 0 && region.Name[0] == '$' {
			keys = rm.Store().LoadKeysFor(region.ID)
		} else {
			keys = []TransportKey{TransportKeyFromRegion(region.Name)}
		}

		for j := range keys {
			if keys[j].CalcTransportCode(pkt) == pkt.TransportCodes[0] {
				return keys[j], true
			}
		}
	}
	return TransportKey{}, false
}
