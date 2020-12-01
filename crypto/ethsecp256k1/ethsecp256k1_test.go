package ethsecp256k1_test

import (
	"encoding/hex"
	"testing"

	ethcrypto "github.com/maticnetwork/bor/crypto"
	"github.com/stretchr/testify/assert"

	"github.com/tendermint/tendermint/crypto/ethsecp256k1"
)

type keyData struct {
	priv            string
	pub             string
	decompressedPub string
	addr            string
}

var secpDataTable = []keyData{
	{
		priv: "e0a4dc43cebe4e4163dda6aec865548e2d54ede5d651a21978ce3c901d651f9d",
		pub:  "04403bdea50c7e1c1e0f806f4f7d8f6e50e693bc16ac678e1b5ce9001e585c075813b34a2b8f6a18ef24d324f11ec53db9f0cf8073b77345e42a1f9e0526507d0c",
		addr: "d9ebA42313c7F08B746ce1860EC326A205154f50",
	},
	{
		priv: "86052a190cfff18052e771b713243a07781bc20c5ed829339e633912e4ef84e2",
		pub:  "049d44ab1627fd1b5836e1365342b7f7063dad1e2f8c7ed9ac9fe065366fbf55f0dc64d67d128642aeceb9596f84a8045a34828f556f9884b979259b7b4efc020e",
		addr: "5B43bc10804Ab182c66ba4d441fdA5A49898cBa4",
	},
}

func TestPubKeyEthsecp256k1Address(t *testing.T) {
	for _, d := range secpDataTable {
		privBytes, _ := hex.DecodeString(d.priv)
		pubBytes, _ := hex.DecodeString(d.pub)
		addrBytes, _ := hex.DecodeString(d.addr)

		var priv ethsecp256k1.PrivKey = ethsecp256k1.PrivKey(privBytes)
		pubKey := priv.PubKey()
		pub, _ := pubKey.(ethsecp256k1.PubKey)

		// decompress pub key
		pubk, err := ethcrypto.DecompressPubkey(pub.Bytes())
		assert.NoError(t, err)

		assert.Equal(t, ethcrypto.FromECDSAPub(pubk), ethsecp256k1.PubKey(pubBytes).Bytes(), "Expected pub keys to match")
		assert.Equal(t, pubKey.Address().Bytes(), addrBytes, "Expected addresses to match")
	}
}

// func TestSignAndValidateSecp256k1(t *testing.T) {
// 	privKey := secp256k1.GenPrivKey()
// 	pubKey := privKey.PubKey()

// 	msg := crypto.CRandBytes(128)
// 	sig, err := privKey.Sign(msg)
// 	require.Nil(t, err)

// 	assert.True(t, pubKey.VerifySignature(msg, sig))

// 	// Mutate the signature, just one bit.
// 	sig[3] ^= byte(0x01)

// 	assert.False(t, pubKey.VerifySignature(msg, sig))
// }

// // This test is intended to justify the removal of calls to the underlying library
// // in creating the privkey.
// func TestSecp256k1LoadPrivkeyAndSerializeIsIdentity(t *testing.T) {
// 	numberOfTests := 256
// 	for i := 0; i < numberOfTests; i++ {
// 		// Seed the test case with some random bytes
// 		privKeyBytes := [32]byte{}
// 		copy(privKeyBytes[:], crypto.CRandBytes(32))

// 		// This function creates a private and public key in the underlying libraries format.
// 		// The private key is basically calling new(big.Int).SetBytes(pk), which removes leading zero bytes
// 		priv, _ := underlyingSecp256k1.PrivKeyFromBytes(underlyingSecp256k1.S256(), privKeyBytes[:])
// 		// this takes the bytes returned by `(big int).Bytes()`, and if the length is less than 32 bytes,
// 		// pads the bytes from the left with zero bytes. Therefore these two functions composed
// 		// result in the identity function on privKeyBytes, hence the following equality check
// 		// always returning true.
// 		serializedBytes := priv.Serialize()
// 		require.Equal(t, privKeyBytes[:], serializedBytes)
// 	}
// }

// func TestGenPrivKeySecp256k1(t *testing.T) {
// 	// curve oder N
// 	N := underlyingSecp256k1.S256().N
// 	tests := []struct {
// 		name   string
// 		secret []byte
// 	}{
// 		{"empty secret", []byte{}},
// 		{
// 			"some long secret",
// 			[]byte("We live in a society exquisitely dependent on science and technology, " +
// 				"in which hardly anyone knows anything about science and technology."),
// 		},
// 		{"another seed used in cosmos tests #1", []byte{0}},
// 		{"another seed used in cosmos tests #2", []byte("mySecret")},
// 		{"another seed used in cosmos tests #3", []byte("")},
// 	}
// 	for _, tt := range tests {
// 		tt := tt
// 		t.Run(tt.name, func(t *testing.T) {
// 			gotPrivKey := secp256k1.GenPrivKeySecp256k1(tt.secret)
// 			require.NotNil(t, gotPrivKey)
// 			// interpret as a big.Int and make sure it is a valid field element:
// 			fe := new(big.Int).SetBytes(gotPrivKey[:])
// 			require.True(t, fe.Cmp(N) < 0)
// 			require.True(t, fe.Sign() > 0)
// 		})
// 	}
// }
