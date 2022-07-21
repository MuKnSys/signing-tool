package main
import "go.dedis.ch/kyber/v3"

type member struct {
  pubfile string
  index int
  pub kyber.Point
  pubhex string
}

func map_pubfile_to_index(members []member) map[string]int {
  var m member
  var result map[string]int = make(map[string]int)
  for _, m = range members { result[m.pubfile] = m.index }
  return result }

/* returns nil if not found */
func find_member_by_pub(pub kyber.Point, members []member) *member {
  var i int
  for i, _ = range members { if members[i].pub.Equal(pub) {return &members[i]} }
  return nil }
