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
	// from the ADVERT (not stored in the store).
	Contact *ContactInfo

	// IsNew is true if a new contact was added to the store.
	IsNew bool

	// Rejected is true if the ADVERT was not processed (replay, invalid, full, etc.).
	Rejected bool

	// RejectReason is a human-readable explanation when Rejected is true.
	RejectReason string
}

// ProcessAdvert handles a received ADVERT packet by verifying the signature,
// checking for replay attacks, and adding or updating the contact in the store.
//
// Parameters:
//   - store: the contact store to query and update
//   - advert: the parsed AdvertPayload (from codec.ParseAdvertPayload)
//   - nowTimestamp: the current local clock time (for LastMod)
//   - autoAdd: whether to automatically add new contacts to the store
//
// This corresponds to the firmware's onAdvertRecv() in BaseChatMesh.
func ProcessAdvert(
	store ContactStore,
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

	// Step 3: look up existing contact by full pubkey
	var advertID core.MeshCoreID
	copy(advertID[:], advert.PubKey[:])

	existing := store.GetByPubKey(advertID)

	// Step 4: replay prevention
	if existing != nil && advert.Timestamp <= existing.LastAdvertTimestamp {
		return AdvertResult{
			Contact:      existing,
			Rejected:     true,
			RejectReason: "possible replay",
		}
	}

	// Step 5: new contact without auto-add
	if existing == nil && !autoAdd {
		temp := populateContactFromAdvert(advert, nowTimestamp)
		return AdvertResult{
			Contact:      temp,
			Rejected:     true,
			RejectReason: "auto-add disabled",
		}
	}

	// Step 6: new contact — add to store
	if existing == nil {
		newContact := populateContactFromAdvert(advert, nowTimestamp)
		stored, err := store.AddContact(newContact)
		if err != nil {
			return AdvertResult{
				Rejected:     true,
				RejectReason: "contacts full",
			}
		}
		return AdvertResult{
			Contact: stored,
			IsNew:   true,
		}
	}

	// Step 7: existing contact — update fields
	updated := &ContactInfo{
		ID:                 existing.ID,
		Name:               advert.AppData.Name,
		Type:               advert.AppData.NodeType,
		Flags:              existing.Flags,
		OutPathLen:         existing.OutPathLen,
		OutPath:            existing.OutPath,
		LastAdvertTimestamp: advert.Timestamp,
		LastMod:            nowTimestamp,
		GPSLat:             existing.GPSLat,
		GPSLon:             existing.GPSLon,
		SyncSince:          existing.SyncSince,
	}
	if advert.AppData.HasLocation() {
		updated.GPSLat = int32(math.Round(*advert.AppData.Lat * codec.CoordScale))
		updated.GPSLon = int32(math.Round(*advert.AppData.Lon * codec.CoordScale))
	}
	_ = store.UpdateContact(updated)

	return AdvertResult{
		Contact: store.GetByPubKey(advertID),
	}
}

// ProcessPath handles a received PATH packet by updating the contact's direct
// routing path and returning any piggybacked extra payload.
//
// Parameters:
//   - store: the contact store to query and update
//   - senderID: the public key of the PATH sender
//   - pathContent: the parsed PathContent (from codec.ParsePathContent)
//   - nowTimestamp: the current local clock time (for LastMod)
//
// Returns the updated contact, the extra type and data (for ACK/RESPONSE
// processing by higher-level code), and any error.
//
// This corresponds to the firmware's onContactPathRecv().
func ProcessPath(
	store ContactStore,
	senderID core.MeshCoreID,
	pathContent *codec.PathContent,
	nowTimestamp uint32,
) (contact *ContactInfo, extraType uint8, extraData []byte, err error) {
	found := store.GetByPubKey(senderID)
	if found == nil {
		return nil, 0, nil, ErrContactNotFound
	}

	// Update the direct routing path directly on the stored reference
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
