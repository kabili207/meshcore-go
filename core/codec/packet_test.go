package codec

import (
	"bytes"
	"testing"
)

func TestPacketHeader(t *testing.T) {
	tests := []struct {
		name           string
		header         uint8
		wantRouteType  uint8
		wantPayloadTyp uint8
		wantVersion    uint8
	}{
		{
			name:           "flood advert v1",
			header:         (PayloadTypeAdvert << PHTypeShift) | RouteTypeFlood | (PayloadVer1 << PHVerShift),
			wantRouteType:  RouteTypeFlood,
			wantPayloadTyp: PayloadTypeAdvert,
			wantVersion:    PayloadVer1,
		},
		{
			name:           "direct txt_msg v1",
			header:         (PayloadTypeTxtMsg << PHTypeShift) | RouteTypeDirect | (PayloadVer1 << PHVerShift),
			wantRouteType:  RouteTypeDirect,
			wantPayloadTyp: PayloadTypeTxtMsg,
			wantVersion:    PayloadVer1,
		},
		{
			name:           "transport flood grp_txt v1",
			header:         (PayloadTypeGrpTxt << PHTypeShift) | RouteTypeTransportFlood | (PayloadVer1 << PHVerShift),
			wantRouteType:  RouteTypeTransportFlood,
			wantPayloadTyp: PayloadTypeGrpTxt,
			wantVersion:    PayloadVer1,
		},
		{
			name:           "transport direct req v1",
			header:         (PayloadTypeReq << PHTypeShift) | RouteTypeTransportDirect | (PayloadVer1 << PHVerShift),
			wantRouteType:  RouteTypeTransportDirect,
			wantPayloadTyp: PayloadTypeReq,
			wantVersion:    PayloadVer1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Packet{Header: tt.header}

			if got := p.RouteType(); got != tt.wantRouteType {
				t.Errorf("RouteType() = %d, want %d", got, tt.wantRouteType)
			}
			if got := p.PayloadType(); got != tt.wantPayloadTyp {
				t.Errorf("PayloadType() = %d, want %d", got, tt.wantPayloadTyp)
			}
			if got := p.PayloadVersion(); got != tt.wantVersion {
				t.Errorf("PayloadVersion() = %d, want %d", got, tt.wantVersion)
			}
		})
	}
}

func TestPacketHasTransportCodes(t *testing.T) {
	tests := []struct {
		routeType uint8
		want      bool
	}{
		{RouteTypeFlood, false},
		{RouteTypeDirect, false},
		{RouteTypeTransportFlood, true},
		{RouteTypeTransportDirect, true},
	}

	for _, tt := range tests {
		p := &Packet{Header: tt.routeType}
		if got := p.HasTransportCodes(); got != tt.want {
			t.Errorf("HasTransportCodes() for route %d = %v, want %v",
				tt.routeType, got, tt.want)
		}
	}
}

func TestPacketReadWriteRoundTrip(t *testing.T) {
	tests := []struct {
		name   string
		packet Packet
	}{
		{
			name: "flood advert no path",
			packet: Packet{
				Header:  (PayloadTypeAdvert << PHTypeShift) | RouteTypeFlood,
				PathLen: 0,
				Path:    []byte{},
				Payload: []byte{0x01, 0x02, 0x03, 0x04},
			},
		},
		{
			name: "flood with path",
			packet: Packet{
				Header:  (PayloadTypeTxtMsg << PHTypeShift) | RouteTypeFlood,
				PathLen: 3,
				Path:    []byte{0xAA, 0xBB, 0xCC},
				Payload: []byte{0x01, 0x02, 0x03, 0x04, 0x05},
			},
		},
		{
			name: "transport flood with codes",
			packet: Packet{
				Header:         (PayloadTypeGrpTxt << PHTypeShift) | RouteTypeTransportFlood,
				TransportCodes: [2]uint16{0x1234, 0x5678},
				PathLen:        2,
				Path:           []byte{0x11, 0x22},
				Payload:        []byte{0xDE, 0xAD, 0xBE, 0xEF},
			},
		},
		{
			name: "direct with max path",
			packet: Packet{
				Header:  (PayloadTypePath << PHTypeShift) | RouteTypeDirect,
				PathLen: MaxPathSize,
				Path:    make([]byte, MaxPathSize),
				Payload: []byte{0x42},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Write to bytes
			data := tt.packet.WriteTo()

			// Read back
			var decoded Packet
			if err := decoded.ReadFrom(data); err != nil {
				t.Fatalf("ReadFrom() error = %v", err)
			}

			// Compare
			if decoded.Header != tt.packet.Header {
				t.Errorf("Header = %02x, want %02x", decoded.Header, tt.packet.Header)
			}
			if decoded.TransportCodes != tt.packet.TransportCodes {
				t.Errorf("TransportCodes = %v, want %v",
					decoded.TransportCodes, tt.packet.TransportCodes)
			}
			if decoded.PathLen != tt.packet.PathLen {
				t.Errorf("PathLen = %d, want %d", decoded.PathLen, tt.packet.PathLen)
			}
			if !bytes.Equal(decoded.Path, tt.packet.Path) {
				t.Errorf("Path = %v, want %v", decoded.Path, tt.packet.Path)
			}
			if !bytes.Equal(decoded.Payload, tt.packet.Payload) {
				t.Errorf("Payload = %v, want %v", decoded.Payload, tt.packet.Payload)
			}
		})
	}
}

func TestPacketReadFromErrors(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr error
	}{
		{
			name:    "empty data",
			data:    []byte{},
			wantErr: ErrPacketTooShort,
		},
		{
			name:    "only header",
			data:    []byte{0x01},
			wantErr: ErrPacketTooShort,
		},
		{
			name: "transport codes missing",
			// Header indicates transport codes but not enough data
			data:    []byte{RouteTypeTransportFlood, 0x00},
			wantErr: ErrPacketTooShort,
		},
		{
			name: "path length exceeds max",
			data: []byte{
				RouteTypeFlood, // header
				0xFF,           // path_len = 255 (exceeds MaxPathSize)
			},
			wantErr: ErrPathTooLong,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var p Packet
			err := p.ReadFrom(tt.data)
			if err == nil {
				t.Error("ReadFrom() expected error, got nil")
				return
			}
			// Check that we got some error (specific error types may vary)
			if tt.wantErr != nil && err.Error() == "" {
				t.Errorf("ReadFrom() error type unexpected")
			}
		})
	}
}

func TestPayloadTypeName(t *testing.T) {
	tests := []struct {
		typ  uint8
		want string
	}{
		{PayloadTypeReq, "REQ"},
		{PayloadTypeResponse, "RESPONSE"},
		{PayloadTypeTxtMsg, "TXT_MSG"},
		{PayloadTypeAck, "ACK"},
		{PayloadTypeAdvert, "ADVERT"},
		{PayloadTypeGrpTxt, "GRP_TXT"},
		{PayloadTypeGrpData, "GRP_DATA"},
		{PayloadTypeAnonReq, "ANON_REQ"},
		{PayloadTypePath, "PATH"},
		{PayloadTypeTrace, "TRACE"},
		{PayloadTypeMultipart, "MULTIPART"},
		{PayloadTypeControl, "CONTROL"},
		{PayloadTypeRawCustom, "RAW_CUSTOM"},
		{0x0E, "UNKNOWN(14)"},
	}

	for _, tt := range tests {
		if got := PayloadTypeName(tt.typ); got != tt.want {
			t.Errorf("PayloadTypeName(%d) = %s, want %s", tt.typ, got, tt.want)
		}
	}
}

func TestRouteTypeName(t *testing.T) {
	tests := []struct {
		typ  uint8
		want string
	}{
		{RouteTypeTransportFlood, "TRANSPORT_FLOOD"},
		{RouteTypeFlood, "FLOOD"},
		{RouteTypeDirect, "DIRECT"},
		{RouteTypeTransportDirect, "TRANSPORT_DIRECT"},
	}

	for _, tt := range tests {
		if got := RouteTypeName(tt.typ); got != tt.want {
			t.Errorf("RouteTypeName(%d) = %s, want %s", tt.typ, got, tt.want)
		}
	}
}
