package contact

import (
	"math"

	"github.com/kabili207/meshcore-go/core"
	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/core/crypto"
)

// AdvertResult describes the outcome of processing a received ADVERT.
type AdvertResult struct {
	// Contact is the contact that was created or updated. For rejected ADVERTs
	// with autoAdd disabled, this contains a temporary ContactInfo populated
	// from the ADVERT (not stored in the manager).
	Contact *ContactInfo

	// IsNew is true if a new contact was added to the manager.
	IsNew bool

	// Rejected is true if the ADVERT was not processed (replay, invalid, full, etc.).
	Rejected bool

	// RejectReason is a human-readable explanation when Rejected is true.
	RejectReason string
}

// ProcessAdvert handles a received ADVERT packet by verifying the signature,
// checking for replay attacks, and adding or updating the contact in the manager.
//
// Parameters:
//   - advert: the parsed AdvertPayload (from codec.ParseAdvertPayload)
//   - nowTimestamp: the current local clock time (for LastMod)
//   - autoAdd: whether to automatically add new contacts to the manager
//
// This corresponds to the firmware's onAdvertRecv() in BaseChatMesh.
func (m *ContactManager) ProcessAdvert(
	advert *codec.AdvertPayload,
	nowTimestamp uint32,
	autoAdd bool,
) AdvertResult {
	// Step 1: validate appdata exists and has a name
	if advert.AppData == nil || advert.AppData.Name == "" {
		return AdvertResult{
			Rejected:     true,
			RejectReason: "advert missing name",
		}
	}

	// Step 2: verify Ed25519 signature
	if !crypto.VerifyAdvert(advert) {
		return AdvertResult{
			Rejected:     true,
			RejectReason: "invalid signature",
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Step 3: look up existing contact by full pubkey
	var advertID core.MeshCoreID
	copy(advertID[:], advert.PubKey[:])

	var existing *ContactInfo
	for _, c := range m.contacts {
		if c.ID == advertID {
			existing = c
			break
		}
	}

	// Step 4: replay prevention
	if existing != nil && advert.Timestamp <= existing.LastAdvertTimestamp {
		m.log.Debug("possible replay attack",
			"peer", advertID.String(),
			"advert_ts", advert.Timestamp,
			"last_ts", existing.LastAdvertTimestamp)
		return AdvertResult{
			Contact:      existing,
			Rejected:     true,
			RejectReason: "possible replay",
		}
	}

	// Step 5: new contact without auto-add
	if existing == nil && !autoAdd {
		// Build a temporary ContactInfo for the caller to inspect
		temp := populateContactFromAdvert(advert, nowTimestamp)
		return AdvertResult{
			Contact:      temp,
			Rejected:     true,
			RejectReason: "auto-add disabled",
		}
	}

	// Step 6: new contact — allocate slot
	if existing == nil {
		slot := m.allocateSlot()
		if slot == nil {
			return AdvertResult{
				Rejected:     true,
				RejectReason: "contacts full",
			}
		}

		temp := populateContactFromAdvert(advert, nowTimestamp)
		slot.ID = temp.ID
		slot.Name = temp.Name
		slot.Type = temp.Type
		slot.OutPathLen = PathUnknown
		slot.OutPath = nil
		slot.LastAdvertTimestamp = temp.LastAdvertTimestamp
		slot.LastMod = temp.LastMod
		slot.GPSLat = temp.GPSLat
		slot.GPSLon = temp.GPSLon
		slot.SyncSince = 0
		slot.InvalidateSharedSecret()

		if m.onContactAdded != nil {
			m.onContactAdded(slot, true)
		}

		return AdvertResult{
			Contact: slot,
			IsNew:   true,
		}
	}

	// Step 7: existing contact — update fields
	existing.Name = advert.AppData.Name
	existing.Type = advert.AppData.NodeType
	if advert.AppData.HasLocation() {
		existing.GPSLat = int32(math.Round(*advert.AppData.Lat * codec.CoordScale))
		existing.GPSLon = int32(math.Round(*advert.AppData.Lon * codec.CoordScale))
	}
	existing.LastAdvertTimestamp = advert.Timestamp
	existing.LastMod = nowTimestamp

	if m.onContactAdded != nil {
		m.onContactAdded(existing, false)
	}

	return AdvertResult{
		Contact: existing,
	}
}

// ProcessPath handles a received PATH packet by updating the contact's direct
// routing path and returning any piggybacked extra payload.
//
// Parameters:
//   - senderID: the public key of the PATH sender
//   - pathContent: the parsed PathContent (from codec.ParsePathContent)
//   - nowTimestamp: the current local clock time (for LastMod)
//
// Returns the updated contact, the extra type and data (for ACK/RESPONSE
// processing by higher-level code), and any error.
//
// This corresponds to the firmware's onContactPathRecv().
func (m *ContactManager) ProcessPath(
	senderID core.MeshCoreID,
	pathContent *codec.PathContent,
	nowTimestamp uint32,
) (contact *ContactInfo, extraType uint8, extraData []byte, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Find the contact
	var found *ContactInfo
	for _, c := range m.contacts {
		if c.ID == senderID {
			found = c
			break
		}
	}
	if found == nil {
		return nil, 0, nil, ErrContactNotFound
	}

	// Update the direct routing path
	found.OutPathLen = int8(pathContent.PathLen)
	if pathContent.PathLen > 0 {
		found.OutPath = make([]byte, pathContent.PathLen)
		copy(found.OutPath, pathContent.Path)
	} else {
		found.OutPath = nil
	}
	found.LastMod = nowTimestamp

	return found, pathContent.ExtraType, pathContent.Extra, nil
}

// populateContactFromAdvert creates a ContactInfo from an ADVERT payload.
// This is the Go equivalent of firmware's populateContactFromAdvert().
func populateContactFromAdvert(advert *codec.AdvertPayload, nowTimestamp uint32) *ContactInfo {
	c := &ContactInfo{
		Name:               advert.AppData.Name,
		Type:               advert.AppData.NodeType,
		OutPathLen:         PathUnknown,
		LastAdvertTimestamp: advert.Timestamp,
		LastMod:            nowTimestamp,
	}
	copy(c.ID[:], advert.PubKey[:])

	if advert.AppData.HasLocation() {
		c.GPSLat = int32(math.Round(*advert.AppData.Lat * codec.CoordScale))
		c.GPSLon = int32(math.Round(*advert.AppData.Lon * codec.CoordScale))
	}

	return c
}
