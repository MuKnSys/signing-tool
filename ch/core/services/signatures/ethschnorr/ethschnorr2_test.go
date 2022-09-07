package ethschnorr

// This code is largely based on go.dedis.ch/kyber/sign/schnorr_test from
// EPFL's DEDIS

import (
	crand "crypto/rand"
	"fmt"
	"math/big"
	mrand "math/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/curve25519"

	"github.com/smartcontractkit/chainlink/core/services/signatures/cryptotest"
	"github.com/smartcontractkit/chainlink/core/services/signatures/secp256k1"
)

var numSignatures = 5

var randomStream = cryptotest.NewStream(&testing.T{}, 0)

var printTests = true

func make_half_q() *big.Int {
  /*
  ref:
  https://github.com/smartcontractkit/chainlink/blob/develop/contracts/src/v0.5/dev/SchnorrSECP256K1.sol
  https://en.bitcoin.it/wiki/Secp256k1
  (defconstant Q #xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141)
  (let ((half-q (1+ (ash Q -1))))
    (format nil "0x~X" (1+ (ash Q -1))))
  ; The result is half_q.
  */
  var result *big.Int = big.NewInt(0)
  var success bool = false
  result, success = result.SetString(
    "0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A1",
    0)
  if !success { panic("bigint trouble"); }
  return result
}

var half_q *big.Int = make_half_q()

func printTest(t *testing.T, msg *big.Int, private kyber.Scalar,
	public kyber.Point, signature Signature) {
	privateBytes, err := private.MarshalBinary()
	require.Nil(t, err)
	pX, pY := secp256k1.Coordinates(public)
  if pX.Cmp(half_q) == -1 { //only print keys valid for ethereum verification
    fmt.Printf("  ['%064x',\n   '%064x',\n   '%064x',\n   '%064x',\n   "+
      "'%064x',\n   '%040x'],\n",
      msg, privateBytes, pX, pY, signature.Signature,
      signature.CommitmentPublicAddress)
  }
}

func TestShortSchnorr_SignAndVerify(t *testing.T) {
	if printTests {
		fmt.Printf("tests = [\n")
	}
	for i := 0; i < numSignatures; i++ {
		rand := mrand.New(mrand.NewSource(0))
		msg, err := crand.Int(rand, u256Cardinality)
		require.NoError(t, err)
		kp := secp256k1.Generate(randomStream)
		sig, err := Sign(kp.Private, msg) // Sign has non-deterministic random num
		require.NoError(t, err, "failed to sign message")
		require.NoError(t, Verify(kp.Public, msg, sig),
			"failed to validate own signature")
		require.Error(t, Verify(kp.Public, u256Cardinality, sig),
			"failed to abort on too large a message")
		require.Error(t, Verify(kp.Public, big.NewInt(0).Neg(big.NewInt(1)), sig),
			"failed to abort on negative message")
		if printTests {
			printTest(t, msg, kp.Private, kp.Public, sig)
		}
		wrongMsg := big.NewInt(0).Add(msg, big.NewInt(1))
		require.Error(t, Verify(kp.Public, wrongMsg, sig),
			"failed to reject signature with bad message")
		wrongPublic := secp256k1Group.Point().Add(kp.Public, kp.Public)
		require.Error(t, Verify(wrongPublic, msg, sig),
			"failed to reject signature with bad public key")
		wrongSignature := &signature{
			CommitmentPublicAddress: sig.CommitmentPublicAddress,
			Signature:               big.NewInt(0).Add(sig.Signature, one),
		}
		require.Error(t, Verify(kp.Public, msg, wrongSignature),
			"failed to reject bad signature")
		badPublicCommitmentAddress := &signature{Signature: sig.Signature}
		copy(badPublicCommitmentAddress.CommitmentPublicAddress[:],
			sig.CommitmentPublicAddress[:])
		badPublicCommitmentAddress.CommitmentPublicAddress[0] ^= 1 // Corrupt it
		require.Error(t, Verify(kp.Public, msg, badPublicCommitmentAddress),
			"failed to reject signature with bad public commitment")
	}
	if printTests {
		fmt.Println("]")
	}
	// Check other validations
	edSuite := curve25519.NewBlakeSHA256Curve25519(false)
	badScalar := edSuite.Scalar()
	_, err := Sign(badScalar, i())
	require.Error(t, err)
	require.Contains(t, err.Error(), "not a secp256k1 scalar")
	err = Verify(edSuite.Point(), i(), NewSignature())
	require.Error(t, err)
	require.Contains(t, err.Error(), "not a secp256k1 point")
	err = Verify(secp256k1Suite.Point(), i(), &signature{Signature: big.NewInt(-1)})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not a valid signature")
	err = Verify(secp256k1Suite.Point(), i(), &signature{Signature: u256Cardinality})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not a valid signature")
}

func TestShortSchnorr_NewSignature(t *testing.T) {
	s := NewSignature()
	require.Equal(t, s.Signature, big.NewInt(0))
}

func TestShortSchnorr_ChallengeHash(t *testing.T) {
	point := secp256k1Group.Point()
	var hash [20]byte
	h, err := ChallengeHash(point, hash, big.NewInt(-1))
	require.Nil(t, h)
	require.Error(t, err)
	require.Contains(t, err.Error(), "msg must be a uint256")
	h, err = ChallengeHash(point, hash, u256Cardinality)
	require.Nil(t, h)
	require.Error(t, err)
	require.Contains(t, err.Error(), "msg must be a uint256")
}
