package main
import "os"
import "fmt"
import "time"
import "go.dedis.ch/kyber/v3"
// import "go.dedis.ch/kyber/v3/share"
// import vss "go.dedis.ch/kyber/v3/share/vss/rabin"
// import "go.dedis.ch/kyber/v3/sign/schnorr"

func main() {
  if (len(os.Args) < 4) {panic("need: <hostconf> <pubfiledir> <secretsdir>")}
  var conf config = load_config(os.Args[1], os.Args[2])
  var layout1 layout = compute_layout(conf)
  var guests map[int]guest = compute_guests(layout1, load_secrets(os.Args[3]))
  start_guests(guests)
  // later, also create protocol objects parallel to guests
  // all guests can use the same net_caller
  var nc *net_caller = &net_caller{client_map: layout1.member_to_addr}
  nc.dial_all(layout1.addrs)
  experiment(nc)
}

func start_guests(guests map[int]guest) {
  var (v guest; addrs []string)
  addrs = make([]string, 0, len(guests))
  for _, v = range guests { addrs = append(addrs, v.addr) }
  start_listeners(unique(addrs)) }

/* loads secret_* from secretsdir. */
func load_secrets(secretsdir string) []kyber.Scalar {
  return unmarshal_secret_keys(load_all(secretsdir, "secret_")) }

func experiment(nc *net_caller) {
  // the rest is experimental
  var response string; var err error
  for ;true; {
    err = (*((*nc).pathways[0])).client.Call("SigServer.Greet", "somebody",
                                             &response)
    // assert_nil(err)
    // observation: client object does not reconnect automatically
    if (err != nil) {fmt.Println("error:", err)} else
                    {fmt.Println("received response:", response)}
    time.Sleep(5*time.Second) }
}
