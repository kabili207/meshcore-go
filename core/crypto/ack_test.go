package crypto

import (
	"encoding/binary"
	"testing"
)

func TestComputeAckHash_Deterministic(t *testing.T) {
	content := make([]byte, 5+5) // timestamp(4) + flags(1) + "hello"
	binary.LittleEndian.PutUint32(content[0:4], 1000)
	content[4] = 0x00 // TxtTypePlain, attempt 0
	copy(content[5:], "hello")

	pubKey := make([]byte, 32)
	pubKey[0] = 0xAA

	hash1 := ComputeAckHash(content, pubKey)
	hash2 := ComputeAckHash(content, pubKey)

	if hash1 != hash2 {
		t.Errorf("ACK hash not deterministic: %08x != %08x", hash1, hash2)
	}
	if hash1 == 0 {
		t.Error("ACK hash should not be zero for non-zero input")
	}
}

func TestComputeAckHash_DifferentContent(t *testing.T) {
	pubKey := make([]byte, 32)
	pubKey[0] = 0xBB

	content1 := make([]byte, 6)
	binary.LittleEndian.PutUint32(content1[0:4], 1000)
	content1[4] = 0x00
	content1[5] = 'A'

	content2 := make([]byte, 6)
	binary.LittleEndian.PutUint32(content2[0:4], 1000)
	content2[4] = 0x00
	content2[5] = 'B'

	hash1 := ComputeAckHash(content1, pubKey)
	hash2 := ComputeAckHash(content2, pubKey)

	if hash1 == hash2 {
		t.Errorf("different content should produce different hashes: %08x", hash1)
	}
}

func TestComputeAckHash_DifferentPubKey(t *testing.T) {
	content := make([]byte, 6)
	binary.LittleEndian.PutUint32(content[0:4], 1000)
	content[4] = 0x00
	content[5] = 'X'

	pubKey1 := make([]byte, 32)
	pubKey1[0] = 0x01

	pubKey2 := make([]byte, 32)
	pubKey2[0] = 0x02

	hash1 := ComputeAckHash(content, pubKey1)
	hash2 := ComputeAckHash(content, pubKey2)

	if hash1 == hash2 {
		t.Errorf("different pub keys should produce different hashes: %08x", hash1)
	}
}

func TestComputeAckHash_DifferentTimestamp(t *testing.T) {
	pubKey := make([]byte, 32)

	content1 := make([]byte, 6)
	binary.LittleEndian.PutUint32(content1[0:4], 1000)
	content1[4] = 0x00
	content1[5] = 'Z'

	content2 := make([]byte, 6)
	binary.LittleEndian.PutUint32(content2[0:4], 2000)
	content2[4] = 0x00
	content2[5] = 'Z'

	hash1 := ComputeAckHash(content1, pubKey)
	hash2 := ComputeAckHash(content2, pubKey)

	if hash1 == hash2 {
		t.Errorf("different timestamps should produce different hashes: %08x", hash1)
	}
}
