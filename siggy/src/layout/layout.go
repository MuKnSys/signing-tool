package main; import ("fmt"; "go.dedis.ch/kyber/v3")

type layout struct { /* value object */
  addrs []string
  addr_members [][]int
  members []member /* sorted */
  member_to_addr map[int]int
}

func compute_layout(conf config) layout {
  var result layout = layout{addrs: conf.addrs}
  result.members = load_and_sort(conf.dir, conf.pubfiles)
  result.addr_members = _conf_members_as_indices(
                          conf,
                          map_pubfile_to_index(result.members))
  result.member_to_addr = _compute_member_to_addr(result.addr_members)
  return result }

func _conf_members_as_indices(conf config, membermap map[string]int) [][]int {
  var i, j int; var ss []string; var s string
  var results [][]int = make([][]int, len(conf.members))
  for i, ss = range conf.members {
    results[i] = make([]int, len(ss))
    for j, s = range ss { results[i][j] = membermap[s] } }
  return results }

func _compute_member_to_addr(member_sets [][]int) map[int]int {
  var i, m int; var ms []int
  var result map[int]int = make(map[int]int)
  for i, ms = range member_sets {
    for _, m = range ms { result[m] = i } }
  return result }

/* a guest is a member hosted locally */
type guest struct { /* value object */
  index int /* in full ordered list of members */
  sec kyber.Scalar
  pub kyber.Point
  addr_index int
  addr string
}

/* ignores secrets whose pub keys are not in layout1.
   returns guests mapped by index. */
func compute_guests(layout1 layout, secrets []kyber.Scalar) map[int]guest {
  var (s kyber.Scalar; results map[int]guest; midx int)
  results = make(map[int]guest)
  var ignored int = 0
  for _, s = range secrets {
    midx = find_member_index(compute_pub(s), layout1.members)
    if midx != -1 {
      var g guest = guest{index: midx, sec: s, pub: layout1.members[midx].pub}
      g.addr_index = layout1.member_to_addr[midx]
      g.addr = layout1.addrs[g.addr_index]
      results[g.index] = g
    } else {
      ignored = ignored + 1
    } }
  if ignored > 0 { fmt.Println("ignored ", ignored, " secrets not in config") }
  return results }
