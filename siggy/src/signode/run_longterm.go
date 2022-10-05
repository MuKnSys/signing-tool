package main; import ("strconv";"fmt";"time")

func run_longterm(members []member, guests map[int]guest) {
  save_longterms(_longterm_loop(members, guests)) }

func _longterm_loop(ms []member, gs map[int]guest) map[int]*DKS {
  var (i int; lts map[int]*DKS; d *DKS; cv bool=false)
  /* observation: iterates only once, prob due to chainlink's suite.Pick() */
  for i=0; !cv; i++ {
    lts = _longterm(ms, gs, "longterm"+strconv.Itoa(i)) /* TODO id security */
    cv = true; for _, d = range lts {cv = (cv && chain_valid(d.Public()))}}
  return lts }

/* returns a map from guest index to key share */
func _longterm(ms []member, gs map[int]guest, id string) map[int]*DKS {
  var (lts map[int]*DKS; gidx int; long dks; ok bool; t time.Time)
  t = time.Now(); fmt.Println("DKG longterm start")
  for gidx, _ = range gs { ensure_active_run(pc_dkg, gidx, id) }
  sleep_for_protocol(pc_dkg)
  fmt.Println("DKG longterm end", time.Since(t))
  lts = make(map[int]*DKS)
  for gidx,_ = range gs {
    long, ok = lookup_dks(gidx, id);
    if !ok{panic("longterm key generation failed")}
    /* DSS paper is ambiguous about how to handle qual<members, so require = */
    if len(long.qual) < len(ms) {panic("some members missing from QUAL")}
    lts[gidx] = long.share }
  return lts }
