package main; import ("os"; "strconv"; "fmt"; "time"; "go.dedis.ch/kyber/v3")

func main() {
  if (len(os.Args) < 5) {
    panic("need: <hostconf> <pubfiledir> <secretsdir> <threshold>")}
  var conf config = load_config(os.Args[1], os.Args[2])
  var layout1 layout = compute_layout(conf)
  var guests map[int]guest = compute_guests(layout1, _load_secrets(os.Args[3]))
  var (threshold int; err error)
  threshold, err = strconv.Atoi(os.Args[4]); assert_nil(err)
  protocol_start(layout1, guests, threshold)
  _experiment(guests, layout1.members) }

/* loads secret_* from secretsdir. */
func _load_secrets(secretsdir string) []kyber.Scalar {
  return unmarshal_secret_keys(slurp_all(secretsdir, "secret_")) }

func _experiment(guests map[int]guest, members []member) {
  var (g guest; ok bool; i int)
  g, ok = guests[0]
  fmt.Println("Press Ctrl-C to terminate")
  if ok {
    fmt.Println("I am the host initiating DKG runs")
    time.Sleep(5 * time.Second) } /* longer than net_caller's retry delay */
  for i = 0; true; i++ {
    if ok {ensure_active_run(pc_dkg, g.index, "r"+strconv.Itoa(i))}//TODO run id
    time.Sleep(5*time.Second) } }
