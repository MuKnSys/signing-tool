/* ./signode config.out test_keys/public/ test_keys/p1_secret/ 2 _
   ./signode config.out test_keys/public/ test_keys/p1_secret/ 2 _ test_keys/p1_secret/longterms_t2 `sha256sum </dev/null | awk '{print $1}'`
   _ can be like this: 2022-09-01T05:50:42+02:00 */
package main;
import ("os"; "strconv"; "time"; "math/big"; "go.dedis.ch/kyber/v3";
        "go.dedis.ch/kyber/v3/share/dkg/rabin")

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
    var lts map[int]*dkg.DistKeyShare = load_longterms(guests, os.Args[6])
    msg, ok = big.NewInt(0).SetString(os.Args[7], 16); if !ok{panic("bad msg")}
    dss_init(lts, msg) }
  protocol_start(at, layout1, guests, threshold)
  time.Sleep(time.Until(at))
  if mode == _mode_longterm {run_longterm(layout1.members, guests)} else
  if mode == _mode_dss      {run_dss(guests, msg) } }

/* loads secret_* from secretsdir. */
func _load_secrets(secretsdir string) []kyber.Scalar {
  return unmarshal_secret_keys(slurp_all(secretsdir, "secret_")) }
