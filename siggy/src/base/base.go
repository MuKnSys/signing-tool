package main
import ("encoding"; "encoding/hex"; "example.com/csprng/csprng";
        "go.dedis.ch/kyber/v3"; "go.dedis.ch/kyber/v3/group/edwards25519")

var suite *edwards25519.SuiteEd25519 = (
  edwards25519.NewBlakeSHA256Ed25519WithRand(csprng.Get()))

// the next two functions are based on dkg_test.go's genPair()
func pick_secret() kyber.Scalar {
  return suite.Scalar().Pick(suite.RandomStream()) }
func compute_pub(secret kyber.Scalar) kyber.Point {
  return suite.Point().Mul(secret, nil) }

func pubhex(pub kyber.Point) string {
  var ba []byte; var err error
  ba, err = pub.MarshalBinary(); assert_nil(err)
  return hex.EncodeToString(ba) }

func unmarshal_public_keys(blobs [][]byte) []kyber.Point {
  return _unmarshal_keys(blobs, make([]kyber.Point, len(blobs)), suite.Point) }

func unmarshal_secret_keys(blobs [][]byte) []kyber.Scalar {
  return _unmarshal_keys(blobs, make([]kyber.Scalar, len(blobs)), suite.Scalar)}

/* result must have same size as blobs */
func _unmarshal_keys[T encoding.BinaryUnmarshaler] (
    blobs [][]byte, result []T, allocator func() T) []T {
  var (i int; ba []byte)
  for i, ba = range blobs {
    result[i] = allocator()
    assert_nil(result[i].UnmarshalBinary(ba)) }
  return result }
