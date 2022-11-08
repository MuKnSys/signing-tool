/* ./signode config.out test_keys/public/ test_keys/p1_secret/ 2 _
   echo 0 _ AA| ./signode config.out test_keys/public/ test_keys/p1_secret/ 2 _\
     test_keys/p1_secret/longterms_t2
   _ can even be like this: 2022-09-01T05:50:42+02:00 */
package main;
import ("os"; "strconv"; "time"; "go.dedis.ch/kyber/v3")

const (_mode_longterm, _mode_dss int = 0, 1)

func main() {
  if (len(os.Args) < 6) {
    panic("need: conf pubdir secdir T dropuntil|_ [longtermfile]")}
  /* dropuntil must be beyond when all nodes have made connections
     as per net_caller.peer_start_grace. Can specify _ if only one process. */
  var mode int; if len(os.Args) == 7 {mode=_mode_dss} else {mode=_mode_longterm}
  var conf config = load_config(os.Args[1], os.Args[2])
  var layout1 layout = compute_layout(conf)
  var guests map[int]guest = compute_guests(layout1, _load_secrets(os.Args[3]))
  var (threshold int; e error; du time.Time)
  threshold, e = strconv.Atoi(os.Args[4]); assert_nil(e)
  if os.Args[5]=="_"{du=time.Now().Add(peer_start_grace+(1*time.Second))} else
                    {du,e=time.Parse(time.RFC3339,os.Args[5]); assert_nil(e)}
  if mode == _mode_dss {
    dss_init(guests, load_longterms(guests, os.Args[6])) }
  protocol_start(du, layout1, guests, threshold)
  var at time.Time = du.Add(50*time.Millisecond + max_drift)
  if mode == _mode_longterm { run_longterm(layout1.members, guests, at) } else
  if mode == _mode_dss { run_sigs(layout1.members, guests, at) } }

/* loads secret_* from secretsdir. */
func _load_secrets(secretsdir string) []kyber.Scalar {
  return unmarshal_secret_keys(slurp_all(secretsdir, "secret_")) }
