package main; import ("time"; "math/big"; "strconv"; "sync")

const (max_drift time.Duration=5*time.Millisecond; /*much shorter than stages*/
       stop_grace time.Duration=1*time.Second)

/* returns run_id */
func run_dkg(members []member, guests map[int]guest, run_id_base string,
             start time.Time) string {
  return _runner_run(members, guests, pc_dkg, _runner_run_id(run_id_base,start),
                     start) }

/* returns run_id */
func run_dss(members []member, guests map[int]guest, run_id_base string,
             start time.Time, doc *big.Int) string {
  var (gidx int; id string)
  id = _runner_run_id(run_id_base, start)
  for gidx, _ = range guests { dss_register_doc(gidx, id, doc) }
  _runner_run(members, guests, pc_dss, id, start)
  for gidx, _ = range guests { dss_deregister_doc(gidx, id) }
  return id }

func _runner_run_id(run_id_base string, start time.Time) string {
  return run_id_base + strconv.FormatInt(start.UnixMilli(), 10) }

func _runner_run(members []member, guests map[int]guest, pc protocol_code,
                 run_id string, start time.Time) string {
  var wg *sync.WaitGroup = &sync.WaitGroup{}
  wg.Add(len(guests))
  var gidx int; for gidx, _ = range guests {
    go _runner_run_guest(gidx, wg, members, pc, run_id, start) }
  wg.Wait()
  return run_id }

func _runner_run_guest(gidx int, wg *sync.WaitGroup, members []member,
                       pc protocol_code, run_id string, start time.Time) {
  defer wg.Done()
  var obs chan int = obs_term(pc, gidx, run_id)
  /* An attacker may try to get us to speak early while some honest peers
     are still dropping messages. So buffer (don't speak) until you're
     sure that all honest peers are at least buffering.
     max_drift should be small so stage doesn't time out while we buffer. */
  var fw_obs = fw_set_allowance(
                 prot_fw, pc, gidx, run_id, start.Add(-max_drift), start,
                 start.Add(protocol_timeout(pc)+stop_grace))
  <-fw_obs /* firewall is now buffering */
  time.Sleep(time.Until(start)); ensure_active_run(pc, gidx, run_id)
  <-obs
  go _runner_cleanup_run(fw_obs, pc, gidx, run_id) }

func _runner_cleanup_run(fw_obs chan int, pc protocol_code, gidx int,
                         run_id string) {
  <-fw_obs; <-fw_obs /* firewall is now closed */
  fw_output(prot_fw)(Message{ProtocolCode: -pc, RecipientIndex: gidx,
                             RunId: run_id}) }
