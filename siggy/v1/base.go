package main
import "encoding/hex"
import "example.com/csprng/csprng"
import "go.dedis.ch/kyber/v3"
import "go.dedis.ch/kyber/v3/group/edwards25519" // fit? copied from test

//correct suite for prod?
var suite *edwards25519.SuiteEd25519 = (
  edwards25519.NewBlakeSHA256Ed25519WithRand(csprng.Get()))

// the next two functions are based on dkg_test.go's genPair()
func pick_secret() kyber.Scalar {
  return suite.Scalar().Pick(suite.RandomStream())
}
func compute_pub(secret kyber.Scalar) kyber.Point {
  return suite.Point().Mul(secret, nil)
}

func pubhex(pub kyber.Point) string {
  var ba []byte; var err error
  ba, err = pub.MarshalBinary(); assert_nil(err)
  return hex.EncodeToString(ba) }
