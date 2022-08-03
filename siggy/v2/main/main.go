package main
import "os"
import "strconv"
import "fmt"
import "time"
import "go.dedis.ch/kyber/v3"
// import "go.dedis.ch/kyber/v3/share"
// import vss "go.dedis.ch/kyber/v3/share/vss/rabin"
// import "go.dedis.ch/kyber/v3/sign/schnorr"

func main() {
  if (len(os.Args) < 5) {
    panic("need: <hostconf> <pubfiledir> <secretsdir> <threshold>")}
  var conf config = load_config(os.Args[1], os.Args[2])
  var layout1 layout = compute_layout(conf)
  var guests map[int]guest = compute_guests(layout1, _load_secrets(os.Args[3]))
  // later, also create protocol objects parallel to guests
  // all guests can use the same net_caller
  var nc *net_caller = new_net_caller(layout1.addrs, layout1.member_to_addr)
  var (threshold int; err error)
  threshold, err = strconv.Atoi(os.Args[4]); assert_nil(err)
  dkg_init(nc, threshold, guests, layout1.members)
  _start_guests(guests)
  nc.dial_all()
  _experiment(nc)
}

func _start_guests(guests map[int]guest) {
  var (v guest; addrs []string)
  addrs = make([]string, 0, len(guests))
  for _, v = range guests { addrs = append(addrs, v.addr) }
  start_listeners(unique(addrs)) }

/* loads secret_* from secretsdir. */
func _load_secrets(secretsdir string) []kyber.Scalar {
  return unmarshal_secret_keys(slurp_all(secretsdir, "secret_")) }

func _experiment_old(nc *net_caller) {
  // the rest is experimental
  var response string; var err error
  for ;true; {
    err = nc.member_client(0).Call("SigServer.Ping", "x", &response)
    // assert_nil(err)
    // observation: client object does not reconnect automatically
    if (err != nil) {fmt.Println("error:", err)} else
                    {fmt.Println("received response:", response)}
    time.Sleep(5*time.Second) }
}
