/* ./signode config.out test_keys/public/ test_keys/p1_secret/ 2 _
   ./signode config.out test_keys/public/ test_keys/p1_secret/ 2 _ test_keys/p1_secret/longterms_t2 `sha256sum </dev/null | awk '{print $1}'`
   _ can be like this: 2022-09-01T05:50:42+02:00 */
package main;
import ("os"; "strconv"; "fmt"; "time"; "math/big"; "errors";
        "go.dedis.ch/kyber/v3"; "go.dedis.ch/kyber/v3/share/dkg/rabin";
        "go.dedis.ch/kyber/v3/share")

const (_mode_longterm, _mode_dss int = 0, 1)

func main() {
  if (len(os.Args) < 6) {
    panic("need: conf pubdir secdir T starttime|_ [longtermfile msghex]")}
  /* starttime must be beyond when all nodes have made connections
     as per net_caller.peer_start_grace. Can specify _ if only one process. */
  var mode int; if len(os.Args) == 8 {mode=_mode_dss} else {mode=_mode_longterm}
  var conf config = load_config(os.Args[1], os.Args[2])
  var layout1 layout = compute_layout(conf)
  var guests map[int]guest = compute_guests(layout1, _load_secrets(os.Args[3]))
  output_init(guests)
  var (threshold int; e error; msg *big.Int; ok bool; at time.Time)
  threshold, e = strconv.Atoi(os.Args[4]); assert_nil(e)
  if os.Args[5]=="_"{at=time.Now().Add(peer_start_grace+(1*time.Second))} else
                    {at,e = time.Parse(time.RFC3339, os.Args[5]); assert_nil(e)}
  if mode == _mode_dss {
    var lts map[int]*dkg.DistKeyShare = _load_longterms(guests, os.Args[6])
    msg, ok = big.NewInt(0).SetString(os.Args[7], 16); if !ok{panic("bad msg")}
    dss_init(lts, msg) }
  protocol_start(at, layout1, guests, threshold)
  time.Sleep(time.Until(at))
  if mode == _mode_longterm {_run_longterm(layout1.members, guests)} else
  if mode == _mode_dss      {_run_dss(guests, msg) } }

/* loads secret_* from secretsdir. */
func _load_secrets(secretsdir string) []kyber.Scalar {
  return unmarshal_secret_keys(slurp_all(secretsdir, "secret_")) }

func _run_longterm(members []member, guests map[int]guest) {
  _save_longterms(_longterm_loop(members, guests)) }

func _longterm_loop(ms []member, gs map[int]guest) map[int]*dkg.DistKeyShare {
  var (i int;lts map[int]*dkg.DistKeyShare;d *dkg.DistKeyShare;cv bool=false)
  /* observation: iterates only once, prob due to chainlink's suite.Pick() */
  for i=0; !cv; i++ {
    lts = _longterm(ms, gs, "longterm"+strconv.Itoa(i))
    cv = true; for _, d = range lts {cv = (cv && chain_valid(d.Public()))}}
  return lts }

/* returns a map from guest index to key share */
func _longterm(ms []member,gs map[int]guest,id string)map[int]*dkg.DistKeyShare{
  var (lts map[int]*dkg.DistKeyShare; gidx int; long dks; ok bool; t time.Time)
  t = time.Now(); fmt.Println("DKG longterm start")
  for gidx, _ = range gs { ensure_active_run(pc_dkg, gidx, id) }
  _sleep_for_protocol(pc_dkg)
  fmt.Println("DKG longterm end", time.Since(t))
  lts = make(map[int]*dkg.DistKeyShare)
  for gidx,_ = range gs {
    long, ok = lookup_dks(gidx, id);
    if !ok{panic("longterm key generation failed")}
    /* DSS paper is ambiguous about how to handle qual<members, so require = */
    if len(long.qual) < len(ms) {panic("some members missing from QUAL")}
    lts[gidx] = long.share }
  return lts }

func _save_longterms(lts map[int]*dkg.DistKeyShare) {
  var (dto map[int]DKSDTO; e error)
  dto, e = _lts_to_dto(lts); assert_nil(e)
  save_gob_to_temp(dto, "longterms_") }

type DKSDTO struct { Commits [][]byte; Share pri_share_dto }

func _lts_to_dto(lts map[int]*dkg.DistKeyShare) (map[int]DKSDTO, error) {
  var (result map[int]DKSDTO = make(map[int]DKSDTO); i int; s *dkg.DistKeyShare)
  for i, s = range lts {
    var (dto DKSDTO;e error); dto,e=_dks_to_dto(s); if e!=nil{return nil,e}
    result[i] = dto }
  return result, nil }

func _dks_to_dto(s *dkg.DistKeyShare) (DKSDTO, error) {
  var (p pri_share_dto; e error; cs [][]byte; c kyber.Point; i int)
  cs = make([][]byte, len((*s).Commits))
  for i, c = range (*s).Commits {
    cs[i], e = c.MarshalBinary(); if e != nil {return DKSDTO{},e} }
  p, e = pri_share_to_dto((*s).Share); if e != nil {return DKSDTO{}, e}
  return DKSDTO {Commits: cs, Share: p}, nil }

func _dto_to_lts(d map[int]DKSDTO) (map[int]*dkg.DistKeyShare, error) {
  var (result map[int]*dkg.DistKeyShare; dksdto DKSDTO; i int; e error)
  result = make(map[int]*dkg.DistKeyShare)
  for i,dksdto=range d {result[i],e=_dto_to_dks(dksdto);if e!=nil{return nil,e}}
  return result, nil }

func _dto_to_dks(dto DKSDTO) (*dkg.DistKeyShare, error) {
  var (cs []kyber.Point; i int; b []byte; e error; s *share.PriShare)
  cs = make([]kyber.Point, len(dto.Commits))
  for i, b = range dto.Commits {
    cs[i]=suite.Point(); e=cs[i].UnmarshalBinary(b); if e!=nil {return nil,e} }
  s, e = dto_to_pri_share(dto.Share); if e!=nil {return nil,e}
  return &dkg.DistKeyShare{Commits: cs, Share: s}, nil }

func _run_dss(guests map[int]guest, msg *big.Int) {
  var (t time.Time; gidx int)
  t = time.Now(); fmt.Println("DKG+DSS start")
  for gidx, _ = range guests { ensure_active_run(pc_dss, gidx, "r0") }
  _sleep_for_protocol(pc_dss)
  fmt.Println("DKG+DSS end", time.Since(t)) }

/* returns a map from guest index to key share */
func _load_longterms(guests map[int]guest,file string)map[int]*dkg.DistKeyShare{
  var lts map[int]*dkg.DistKeyShare = _load_longterms1(file)
  assert_nil(_verify_keys_subset(guests, lts)); return lts }

func _load_longterms1(file string) map[int]*dkg.DistKeyShare {
  var (dto map[int]DKSDTO; e error; lts map[int]*dkg.DistKeyShare)
  load_gob(&dto, file); lts, e = _dto_to_lts(dto); assert_nil(e); return lts }

func _verify_keys_subset[Q,R any](xs map[int]Q, ys map[int]R) error {
  var (k int; ok bool)
  for k,_ = range xs {_,ok = ys[k]; if !ok {return errors.New("map is short")}}
  return nil }

func _sleep_for_protocol(pc protocol_code) {
  time.Sleep(protocol_timeout(pc) + (50*time.Millisecond)) }
