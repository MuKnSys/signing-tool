package main; import ("sync"; "go.dedis.ch/kyber/v3/share/dkg/rabin")

type dks struct { /* value object */
  share *dkg.DistKeyShare
  qual []int
}
/* guest index to run id to dks */ /* TODO GC */
var dkss map[int]map[string]dks = make(map[int]map[string]dks)
var dkss_lck *sync.Mutex = &sync.Mutex{}

func output_init(guests map[int]guest) {
  var idx int; for idx, _ = range guests { dkss[idx] = make(map[string]dks) } }

func note_dks(guest_idx int,run_id string,share *dkg.DistKeyShare,qual []int) {
  dkss_lck.Lock(); defer dkss_lck.Unlock()
  dkss[guest_idx][run_id] = dks {share: share, qual: qual} }

func lookup_dks(guest_idx int, run_id string) (dks, bool) {
  var (result dks; ok bool)
  dkss_lck.Lock(); defer dkss_lck.Unlock()
  result, ok = dkss[guest_idx][run_id]
  return result, ok }
