package main; import ("os"; "strconv"; "fmt"; "time"; "go.dedis.ch/kyber/v3")

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
  _experiment(nc, guests, layout1.members)
}

func _start_guests(guests map[int]guest) {
  var (v guest; addrs []string)
  addrs = make([]string, 0, len(guests))
  for _, v = range guests { addrs = append(addrs, v.addr) }
  start_listeners(unique(addrs)) }

/* loads secret_* from secretsdir. */
func _load_secrets(secretsdir string) []kyber.Scalar {
  return unmarshal_secret_keys(slurp_all(secretsdir, "secret_")) }

func _experiment(nc *net_caller, guests map[int]guest, members []member) {
  var (g guest; ok bool)
  g, ok = guests[0]
  if ok {
    time.Sleep(5 * time.Second) /* longer than net_caller's retry delay */
    fmt.Println("I am initiating a DKG run")
    ensure_active_dkg(g, "test run")
  }
  time.Sleep(60*time.Second)
}
