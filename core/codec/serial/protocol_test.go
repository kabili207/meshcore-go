package serial

import "testing"

func TestCommandConstants(t *testing.T) {
	// Test that new v1.15.0 commands have correct values
	if CmdSendChannelData != 62 {
		t.Errorf("CmdSendChannelData = %d, want 62", CmdSendChannelData)
	}
	if CmdSetDefaultFloodScope != 63 {
		t.Errorf("CmdSetDefaultFloodScope = %d, want 63", CmdSetDefaultFloodScope)
	}
	if CmdGetDefaultFloodScope != 64 {
		t.Errorf("CmdGetDefaultFloodScope = %d, want 64", CmdGetDefaultFloodScope)
	}

	// Test renamed command
	if CmdSetFloodScopeKey != 54 {
		t.Errorf("CmdSetFloodScopeKey = %d, want 54", CmdSetFloodScopeKey)
	}
}

func TestResponseConstants(t *testing.T) {
	// Test new v1.15.0 response codes
	if RespCodeChannelDataRecv != 27 {
		t.Errorf("RespCodeChannelDataRecv = %d, want 27", RespCodeChannelDataRecv)
	}
	if RespCodeDefaultFloodScope != 28 {
		t.Errorf("RespCodeDefaultFloodScope = %d, want 28", RespCodeDefaultFloodScope)
	}
}

func TestStatsTypes(t *testing.T) {
	if StatsTypeCore != 0 {
		t.Errorf("StatsTypeCore = %d, want 0", StatsTypeCore)
	}
	if StatsTypeRadio != 1 {
		t.Errorf("StatsTypeRadio = %d, want 1", StatsTypeRadio)
	}
	if StatsTypePackets != 2 {
		t.Errorf("StatsTypePackets = %d, want 2", StatsTypePackets)
	}
}

func TestSpecialConstants(t *testing.T) {
	if PathLenUnknown != 0xFF {
		t.Errorf("PathLenUnknown = 0x%02X, want 0xFF", PathLenUnknown)
	}
	if MaxChannelDataLength != 247 {
		t.Errorf("MaxChannelDataLength = %d, want 247", MaxChannelDataLength)
	}
}
