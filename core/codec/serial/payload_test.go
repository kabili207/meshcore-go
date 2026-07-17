package serial

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestSelfInfoEncode(t *testing.T) {
	var pk [32]byte
	for i := range pk {
		pk[i] = byte(i)
	}
	s := &SelfInfo{
		AdvType:    1,
		TxPower:    22,
		MaxTxPower: 30,
		PublicKey:  pk,
		AdvLat:     47_500000, // 47.5 deg
		AdvLon:     -122_000000,
		RadioFreq:  915000, // 915.0 MHz in kHz
		RadioBw:    250000, // 250 kHz in Hz
		RadioSf:    11,
		RadioCr:    5,
		Name:       "meshy",
	}
	b := s.Encode()

	if len(b) != 58+len("meshy") {
		t.Fatalf("length = %d, want %d", len(b), 58+len("meshy"))
	}
	if b[0] != RespCodeSelfInfo || b[1] != 1 || b[2] != 22 || b[3] != 30 {
		t.Errorf("header bytes = %x", b[:4])
	}
	if !bytes.Equal(b[4:36], pk[:]) {
		t.Error("public key mismatch")
	}
	if got := int32(binary.LittleEndian.Uint32(b[36:40])); got != 47_500000 {
		t.Errorf("advLat = %d", got)
	}
	if got := int32(binary.LittleEndian.Uint32(b[40:44])); got != -122_000000 {
		t.Errorf("advLon = %d", got)
	}
	if got := binary.LittleEndian.Uint32(b[48:52]); got != 915000 {
		t.Errorf("radioFreq = %d, want 915000", got)
	}
	if got := binary.LittleEndian.Uint32(b[52:56]); got != 250000 {
		t.Errorf("radioBw = %d, want 250000", got)
	}
	if b[56] != 11 || b[57] != 5 {
		t.Errorf("sf/cr = %d/%d", b[56], b[57])
	}
	if string(b[58:]) != "meshy" {
		t.Errorf("name tail = %q", b[58:])
	}
}

func TestDeviceInfoEncode(t *testing.T) {
	d := &DeviceInfo{
		FirmwareVerCode:  13,
		MaxContactsDiv2:  128,
		MaxGroupChannels: 8,
		BuildDate:        "6 Jun 2026",
		Manufacturer:     "meshcore-go",
		FirmwareVersion:  "v1.16.0",
	}
	b := d.Encode()

	if len(b) != 82 {
		t.Fatalf("length = %d, want 82 (fixed layout)", len(b))
	}
	if b[0] != RespCodeDeviceInfo || b[1] != 13 || b[2] != 128 || b[3] != 8 {
		t.Errorf("header = %x", b[:4])
	}
	// Build date: fixed 12-byte NUL-terminated field at [8:20].
	if string(b[8:8+len("6 Jun 2026")]) != "6 Jun 2026" || b[19] != 0 {
		t.Errorf("build date field = %q", b[8:20])
	}
	// Manufacturer: fixed 40-byte field at [20:60]; the official app reads
	// firmware version from offset 60, so these offsets are load-bearing.
	if string(b[20:20+len("meshcore-go")]) != "meshcore-go" || b[59] != 0 {
		t.Errorf("manufacturer field = %q", b[20:60])
	}
	// FirmwareVersion: fixed 20-byte field at [60:80].
	if string(b[60:60+len("v1.16.0")]) != "v1.16.0" || b[79] != 0 {
		t.Errorf("firmware version field = %q", b[60:80])
	}
}

func TestContactEncode(t *testing.T) {
	var pk [32]byte
	pk[0], pk[31] = 0xAA, 0xBB
	c := &Contact{
		PublicKey:  pk,
		Type:       1,
		Flags:      0,
		OutPathLen: 0xFF, // unknown route
		OutPath:    []byte{0x01, 0x02},
		Name:       "Alice",
		LastAdvert: 1_700_000_000,
		GPSLat:     47_000000,
		GPSLon:     -122_000000,
		LastMod:    1_700_000_500,
	}
	b := c.Encode()

	if len(b) != 148 {
		t.Fatalf("length = %d, want 148", len(b))
	}
	if b[0] != RespCodeContact {
		t.Errorf("code = %d", b[0])
	}
	if !bytes.Equal(b[1:33], pk[:]) {
		t.Error("pubkey mismatch")
	}
	if b[33] != 1 || b[34] != 0 || b[35] != 0xFF {
		t.Errorf("type/flags/outpathlen = %d/%d/%d", b[33], b[34], b[35])
	}
	if b[36] != 0x01 || b[37] != 0x02 || b[38] != 0x00 {
		t.Errorf("outpath prefix/padding = %x", b[36:40])
	}
	if string(b[100:105]) != "Alice" || b[131] != 0 {
		t.Errorf("name field = %q (terminator %d)", b[100:132], b[131])
	}
	if binary.LittleEndian.Uint32(b[132:136]) != 1_700_000_000 {
		t.Error("lastAdvert mismatch")
	}
	if int32(binary.LittleEndian.Uint32(b[136:140])) != 47_000000 {
		t.Error("gpsLat mismatch")
	}
	if binary.LittleEndian.Uint32(b[144:148]) != 1_700_000_500 {
		t.Error("lastMod mismatch")
	}
}

func TestContactOutPathTruncated(t *testing.T) {
	// An over-long out-path must be truncated to 64 bytes, not overrun the frame.
	c := &Contact{OutPath: bytes.Repeat([]byte{0x7F}, 100)}
	b := c.Encode()
	if len(b) != 148 {
		t.Fatalf("length = %d, want 148", len(b))
	}
	if b[99] != 0x7F {
		t.Error("last out-path byte should be filled")
	}
	if b[100] != 0 { // name empty -> first name byte is 0, not out-path spill
		t.Errorf("out-path spilled into name field: %x", b[100])
	}
}

func TestSmallFrameEncoders(t *testing.T) {
	if got := EncodeCurrTime(1234); !bytes.Equal(got, []byte{RespCodeCurrTime, 0xD2, 0x04, 0x00, 0x00}) {
		t.Errorf("EncodeCurrTime = %x", got)
	}
	if got := EncodeContactsStart(2); !bytes.Equal(got, []byte{RespCodeContactsStart, 0x02, 0, 0, 0}) {
		t.Errorf("EncodeContactsStart = %x", got)
	}
	if got := EncodeEndOfContacts(5); !bytes.Equal(got, []byte{RespCodeEndOfContacts, 0x05, 0, 0, 0}) {
		t.Errorf("EncodeEndOfContacts = %x", got)
	}
	if got := EncodeOK(); !bytes.Equal(got, []byte{RespCodeOK}) {
		t.Errorf("EncodeOK = %x", got)
	}
	if got := EncodeErr(ErrCodeNotFound); !bytes.Equal(got, []byte{RespCodeErr, ErrCodeNotFound}) {
		t.Errorf("EncodeErr = %x", got)
	}
}

func TestParseAppStart(t *testing.T) {
	// [code][7 reserved]["MeshMon"]
	payload := append([]byte{CmdAppStart, 1, 0, 0, 0, 0, 0, 0}, []byte("MeshMon")...)
	name, err := ParseAppStart(payload)
	if err != nil || name != "MeshMon" {
		t.Fatalf("ParseAppStart = %q, %v", name, err)
	}
	if _, err := ParseAppStart([]byte{CmdAppStart, 1}); err == nil {
		t.Error("expected error for short frame")
	}
}

func TestParseDeviceQuery(t *testing.T) {
	ver, err := ParseDeviceQuery([]byte{CmdDeviceQuery, 3})
	if err != nil || ver != 3 {
		t.Fatalf("ParseDeviceQuery = %d, %v", ver, err)
	}
}

func TestParseGetContactsSince(t *testing.T) {
	if _, has := ParseGetContactsSince([]byte{CmdGetContacts}); has {
		t.Error("bare request should have no since")
	}
	since, has := ParseGetContactsSince([]byte{CmdGetContacts, 0x10, 0, 0, 0})
	if !has || since != 0x10 {
		t.Errorf("since = %d, has = %v", since, has)
	}
}

func TestParseSetDeviceTime(t *testing.T) {
	epoch, err := ParseSetDeviceTime([]byte{CmdSetDeviceTime, 0x00, 0x01, 0x00, 0x00})
	if err != nil || epoch != 0x100 {
		t.Fatalf("ParseSetDeviceTime = %d, %v", epoch, err)
	}
}
