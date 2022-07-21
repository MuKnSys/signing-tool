package main
import "fmt"
import "sort"
import "encoding"
import "go.dedis.ch/kyber/v3"

type layout struct {
  addrs []string
  addr_members [][]int
  members []member /* sorted */
  member_to_addr map[int]int
}

func compute_layout(conf config) layout {
  var result layout = layout{addrs: conf.addrs}
  result.members = compute_sorted_members(conf)
  result.addr_members = conf_members_as_indices(
                          conf,
                          map_pubfile_to_index(result.members))
  result.member_to_addr = compute_member_to_addr(result.addr_members)
  return result }

/* the goal of sorting is for everyone to agree on order of members.
   we sort by pub key assuming that all equal points are marshalled to the same
   byte sequence.
   that is true at least for the implementation of edwards25519 we are using. */
func compute_sorted_members(conf config) []member {
  var (i int; p kyber.Point; pubkeys []kyber.Point)
  pubkeys = unmarshal_public_keys(load_all1(conf.dir, conf.pubfiles))
  var results []member = make([]member, len(conf.pubfiles))
  for i, p = range pubkeys {
    results[i] = member{ pubfile: conf.pubfiles[i], pub: p, pubhex: pubhex(p)} }
  sort.Slice(results,
             func(i,j int) bool {return results[i].pubhex < results[j].pubhex})
  for i, _ = range results { results[i].index = i }
  return results }

func unmarshal_public_keys(blobs [][]byte) []kyber.Point {
  return unmarshal_keys(blobs, make([]kyber.Point, len(blobs)), suite.Point) }

func unmarshal_secret_keys(blobs [][]byte) []kyber.Scalar {
  return unmarshal_keys(blobs, make([]kyber.Scalar, len(blobs)), suite.Scalar) }

/* result must have same size as blobs */
func unmarshal_keys[T encoding.BinaryUnmarshaler](
    blobs [][]byte, result []T, allocator func() T) []T{
  var (i int; ba []byte)
  for i, ba = range blobs {
    result[i] = allocator()
    assert_nil(result[i].UnmarshalBinary(ba)) }
  return result }

func conf_members_as_indices(conf config, membermap map[string]int) [][]int {
  var i, j int; var ss []string; var s string
  var results [][]int = make([][]int, len(conf.members))
  for i, ss = range conf.members {
    results[i] = make([]int, len(ss))
    for j, s = range ss { results[i][j] = membermap[s] } }
  return results }

func compute_member_to_addr(member_sets [][]int) map[int]int {
  var i, m int; var ms []int
  var result map[int]int = make(map[int]int)
  for i, ms = range member_sets {
    for _, m = range ms { result[m] = i } }
  return result }

type guest struct {
  index int /* in full ordered list of members */
  sec kyber.Scalar
  pub kyber.Point
  addr_index int
  addr string
}

/* ignores secrets whose pub keys are not in layout1.
   returns guests mapped by index. */
func compute_guests(layout1 layout, secrets []kyber.Scalar) map[int]guest {
  var (s kyber.Scalar; results map[int]guest; m *member)
  results = make(map[int]guest)
  var ignored int = 0
  for _, s = range secrets {
    m = find_member_by_pub(compute_pub(s), layout1.members)
    if m != nil {
      var g guest = guest{index: (*m).index, sec: s, pub: (*m).pub}
      g.addr_index = layout1.member_to_addr[(*m).index]
      g.addr = layout1.addrs[g.addr_index]
      results[g.index] = g
    } else {
      ignored = ignored + 1
    }
  }
  if ignored > 0 { fmt.Println("ignored ", ignored, " secrets not in config") }
  return results }
