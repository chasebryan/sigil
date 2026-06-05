package sigilcrypto

import (
	"bytes"
	"strings"
	"testing"
)

func TestDigestBytesSHA256(t *testing.T) {
	got, err := DigestBytes([]byte("abc"), "sha256")
	if err != nil {
		t.Fatal(err)
	}
	const want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if got.Hex != want {
		t.Fatalf("SHA-256 mismatch: got %s want %s", got.Hex, want)
	}
}

func TestHMACRejectsDeprecatedHash(t *testing.T) {
	_, err := HMACBytes([]byte("data"), []byte("0123456789abcdef"), "md5")
	if err == nil {
		t.Fatal("expected deprecated HMAC hash rejection")
	}
}

func TestXORUtilities(t *testing.T) {
	left, _ := DecodeInput("1c0111001f010100061a024b53535009181c", "hex")
	right, _ := DecodeInput("686974207468652062756c6c277320657965", "hex")
	got, err := FixedXOR(left, right)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeOutput(got, "hex")
	if err != nil {
		t.Fatal(err)
	}
	const want = "746865206b696420646f6e277420706c6179"
	if encoded != want {
		t.Fatalf("fixed XOR mismatch: got %s want %s", encoded, want)
	}

	repeated, err := RepeatingXOR([]byte("aaaa"), []byte{0x01, 0x02})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(repeated, []byte{0x60, 0x63, 0x60, 0x63}) {
		t.Fatalf("unexpected repeating XOR output: %x", repeated)
	}
}

func TestEd25519SignVerify(t *testing.T) {
	pair, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	signature, err := SignBytes(pair.PrivatePEM, []byte("sigil message"))
	if err != nil {
		t.Fatal(err)
	}
	ok, err := VerifyBytes(pair.PublicPEM, signature, []byte("sigil message"))
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected signature to verify")
	}
	ok, err = VerifyBytes(pair.PublicPEM, signature, []byte("changed"))
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("changed message unexpectedly verified")
	}
}

func TestSealOpenRoundTripAndTamperReject(t *testing.T) {
	plain := []byte(strings.Repeat("sigil cryptology bench\n", 500))
	var sealed bytes.Buffer
	_, err := Seal(&sealed, bytes.NewReader(plain), SealOptions{
		Passphrase: "correct horse battery staple",
		Iterations: 100000,
		ChunkSize:  4096,
	})
	if err != nil {
		t.Fatal(err)
	}

	var opened bytes.Buffer
	_, err = Open(&opened, bytes.NewReader(sealed.Bytes()), "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened.Bytes(), plain) {
		t.Fatal("opened plaintext mismatch")
	}

	tampered := append([]byte(nil), sealed.Bytes()...)
	tampered[len(tampered)-1] ^= 0x01
	_, err = Open(ioDiscard{}, bytes.NewReader(tampered), "correct horse battery staple")
	if err == nil {
		t.Fatal("tampered seal stream unexpectedly opened")
	}
}

func TestEntropyReport(t *testing.T) {
	report := AnalyzeBytes([]byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
	if report.Size != 32 {
		t.Fatalf("size mismatch: %d", report.Size)
	}
	if report.UniqueBytes != 1 {
		t.Fatalf("unique byte mismatch: %d", report.UniqueBytes)
	}
	if report.ShannonBitsPerByte != 0 {
		t.Fatalf("entropy mismatch: %f", report.ShannonBitsPerByte)
	}
}

func TestProfileBytesReportsBitAndCoincidenceStats(t *testing.T) {
	report := ProfileBytes([]byte{0xff, 0x00, 0xff, 0x00}, ProfileOptions{})
	if report.Size != 4 {
		t.Fatalf("profile size mismatch: %d", report.Size)
	}
	if report.BitStats.OneRatio != 0.5 {
		t.Fatalf("one ratio mismatch: %f", report.BitStats.OneRatio)
	}
	if report.BitStats.LongestOneBitRun != 8 || report.BitStats.LongestZeroBitRun != 8 {
		t.Fatalf("unexpected bit runs: ones=%d zeros=%d", report.BitStats.LongestOneBitRun, report.BitStats.LongestZeroBitRun)
	}
	if report.ByteStats.UniqueBytes != 2 {
		t.Fatalf("unique byte mismatch: %d", report.ByteStats.UniqueBytes)
	}
	if len(report.Autocorrelation) == 0 {
		t.Fatal("expected autocorrelation entries")
	}
}

func TestProfileBytesDetectsRepeatedBlocks(t *testing.T) {
	block := []byte("0123456789abcdef")
	data := bytes.Repeat(block, 6)
	report := ProfileBytes(data, ProfileOptions{})

	var sixteen BlockRepeatReport
	for _, item := range report.BlockRepeats {
		if item.BlockSize == 16 {
			sixteen = item
			break
		}
	}
	if sixteen.Blocks != 6 {
		t.Fatalf("16-byte block count mismatch: %d", sixteen.Blocks)
	}
	if sixteen.DuplicateBlocks != 5 {
		t.Fatalf("duplicate block count mismatch: %d", sixteen.DuplicateBlocks)
	}
	if report.Assessment != "repeated-block structure candidate" {
		t.Fatalf("unexpected assessment: %q", report.Assessment)
	}
}

type ioDiscard struct{}

func (ioDiscard) Write(p []byte) (int, error) {
	return len(p), nil
}
