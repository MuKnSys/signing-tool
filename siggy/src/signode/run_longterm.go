package main; import ("fmt"; "strconv"; "time")

func run_longterm(members []member, guests map[int]guest, start time.Time) {
  save_longterms(_longterm_loop(members, guests, start)) }

const (_lt_grace time.Duration = 1 * time.Second)

func _longterm_loop(ms []member, gs map[int]guest, start time.Time)map[int]*DKS{
  var (i int; at time.Time; lts map[int]*DKS; d *DKS; cv bool = false;
       r string = "longterm"+strconv.FormatInt(start.UnixMilli(), 10)
       interval time.Duration=protocol_timeout(pc_dkg)+_lt_grace)
  /* observation: iterates only once, prob due to chainlink's suite.Pick() */
  at = start
  for i=0; !cv; i++ {
    lts = _longterm(ms, gs, r+strconv.Itoa(i), at)
    cv = true; for _, d = range lts {cv = (cv && chain_valid(d.Public()))}
    at=at.Add(interval) }
  return lts }

/* returns a map from guest index to key share */
func _longterm(ms []member, gs map[int]guest, run_id_base string,
               at time.Time) map[int]*DKS {
  var (lts map[int]*DKS;gidx int;long dks;output prot_output;ok bool;id string)
  id = run_dkg(ms, gs, run_id_base, at)
  lts = make(map[int]*DKS)
  for gidx,_ = range gs {
    output, ok = pop_output(pc_dkg, gidx, id);
    if !ok{panic("longterm key generation failed")}
    long = output.(dks)
    /* DSS paper is ambiguous about how to handle qual<members, so require = */
    if len(long.qual) < len(ms) {panic("some members missing from QUAL")}
    fmt.Println("success for guest index", gidx, long.share)
    lts[gidx] = long.share }
  return lts }
