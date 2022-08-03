package main
import "sort"
import "go.dedis.ch/kyber/v3"

type member struct { /* value object */
  pubfile string
  index int
  pub kyber.Point
  pubhex string
}

/* the goal of sorting is for everyone to agree on order of members.
   we sort by pub key assuming that all equal points are marshalled to the same
   byte sequence.
   that is true at least for the implementation of edwards25519 we are using. */
func load_and_sort(dir string, pubfiles []string) []member {
  var (i int; p kyber.Point; pubkeys []kyber.Point)
  pubkeys = unmarshal_public_keys(slurp_all1(dir, pubfiles))
  var results []member = make([]member, len(pubfiles))
  for i, p = range pubkeys {
    results[i] = member{ pubfile: pubfiles[i], pub: p, pubhex: pubhex(p)} }
  sort.Slice(results,
             func(i,j int) bool {return results[i].pubhex < results[j].pubhex})
  for i, _ = range results { results[i].index = i }
  return results }

func map_pubfile_to_index(members []member) map[string]int {
  var m member
  var result map[string]int = make(map[string]int)
  for _, m = range members { result[m.pubfile] = m.index }
  return result }

/* returns -1 if not found */
func find_member_index(pub kyber.Point, members []member) int {
  var (i int; m member)
  for i, m = range members { if m.pub.Equal(pub) {return i} }
  return -1 }

func member_pubs(members []member) []kyber.Point {
  var (result []kyber.Point; i int; m member)
  result = make([]kyber.Point, len(members))
  for i, m = range(members) { result[i] = m.pub }
  return result }
