package main
import (
  "math/big"; "sync"
  "github.com/smartcontractkit/chainlink/core/services/signatures/ethdss"
  "github.com/smartcontractkit/chainlink/core/services/signatures/ethschnorr"
  "go.dedis.ch/kyber/v3/share/dkg/rabin"
  "go.dedis.ch/kyber/v3")

/* guest index to longterm key share */
var _longterms map[int]*dkg.DistKeyShare = make(map[int]*dkg.DistKeyShare)
/* guest_index to run_id to document */
var _docs map[int]map[string]*big.Int = map[int]map[string]*big.Int{}
var _dss_lck *sync.Mutex = &sync.Mutex{}

const (_op_dss_partsig int = op_dkg_final + 2)

func init() {
  register_protocol(
    protocol{code:pc_dss, make_kyber_dat:make_dss_kdat, stages:dss_stages(),
             cleanup: func(r *protocol_run) {dss_cleanup(r); dkg_cleanup(r);}})}

func dss_init(guests map[int]guest, longterms map[int]*dkg.DistKeyShare) {
  var (gidx int)
  _dss_lck.Lock(); defer _dss_lck.Unlock();
  for gidx, _ = range guests { _docs[gidx] = make(map[string]*big.Int) }
  _longterms = longterms;}

func dss_register_doc(guest_index int, run_id string, doc *big.Int) {
  _dss_lck.Lock(); _docs[guest_index][run_id] = doc; _dss_lck.Unlock(); }
func dss_deregister_doc(guest_index int, run_id string) {
  _dss_lck.Lock(); delete(_docs[guest_index], run_id); _dss_lck.Unlock() }

func _longterm1(r *protocol_run) *dkg.DistKeyShare {
  _dss_lck.Lock(); defer _dss_lck.Unlock(); return _longterms[(*r).guest_index]}

func _doc_for(r *protocol_run) *big.Int {
  _dss_lck.Lock(); defer _dss_lck.Unlock();
  return _docs[(*r).guest_index][(*r).id] }

func dss_stages() []protocol_stage {
  var result []protocol_stage = make([]protocol_stage, 0, 20)
  result = append(result, lookup_protocol(pc_dkg).stages...)
  result = append(result,
             ps(st_init,nil,nil,nil,nil),
             ps(st_partsig,pr_partsig,dto_to_partsig,
                dss_partsig_v,PartSigDTO{}),
             ps(dss_st_final,nil,nil,nil,nil))
  return result }

type kdat_args struct { /* value object */
  secret kyber.Scalar
  participants []kyber.Point
  threshold int
}
var dss_kdat_args map[any]kdat_args = make(map[any]kdat_args)
var dss_kdat_lck *sync.Mutex = &sync.Mutex{}
var dss_kdats map[*protocol_run]*clientdss.DSS =
  make(map[*protocol_run]*clientdss.DSS)
func dss_kdat(r *protocol_run) *clientdss.DSS {
  dss_kdat_lck.Lock(); defer dss_kdat_lck.Unlock()
  return dss_kdats[r] }
func dss_cleanup(r *protocol_run) {
  dss_kdat_lck.Lock(); defer dss_kdat_lck.Unlock()
  delete(dss_kdat_args, (*r).kyber_dat)
  delete(dss_kdats, r) }

func make_dss_kdat(g guest, members []member, threshold int) (any, error) {
  var (result any; e error)
  result, e = make_dkg_kdat(g, members, threshold); if e != nil {return nil, e}
  dss_kdat_lck.Lock(); defer dss_kdat_lck.Unlock()
  /* ugliness: the first few calls to this function are only for verification.
               but we still store them and their dss_kdat_args forever. */
  dss_kdat_args[result] = kdat_args{secret: g.sec,
                                    participants: member_pubs(members),
                                    threshold: threshold}
  return result, nil }

func st_init(r *protocol_run) {
  var (gen *dkg.DistKeyGenerator;random *dkg.DistKeyShare;e error;a kdat_args)
  gen = (*r).kyber_dat.(*dkg.DistKeyGenerator)
  random, e = gen.DistKeyShare(); if e != nil {abandon(r); return}
  dss_kdat_lck.Lock(); defer dss_kdat_lck.Unlock()
  a = dss_kdat_args[gen]
  dss_kdats[r], e = clientdss.NewDSS(clientdss.DSSArgs{
                      Secret: a.secret, Participants: a.participants,
                      Long: _longterm1(r), Random: random,
                      H2: gen.QUAL(), Msg: _doc_for(r),
                      T: a.threshold })
  if e != nil {warn(e); abandon(r); return} /* error won't happen so late */ }

func st_partsig(r *protocol_run) {
  var (sig *clientdss.PartialSig; e error)
  sig, e = dss_kdat(r).PartialSig(); if e!=nil {warn(e); abandon(r); return}
  broadcast_qual(r, _op_dss_partsig, sig, partsig_to_dto) }

func pr_partsig(r *protocol_run, sig any) {
  warn_if_err(dss_kdat(r).ProcessPartialSig(sig.(*clientdss.PartialSig))) }

func dss_st_final(r *protocol_run) {
  var (s ethschnorr.Signature; e error)
  if !dss_kdat(r).EnoughPartialSig() {abandon(r); return}
  s, e = dss_kdat(r).Signature(); if e != nil {warn(e); abandon(r); return}
  push_output(pc_dss, (*r).guest_index, (*r).id, s)
  /* sanity check, during development
     e = clientdss.Verify(_longterm1(r).Commitments()[0], _doc_for(r), s)
     if e != nil { warn(e) } else { fmt.Println("verification succeeded") } */ }

/* validators */

func dss_partsig_v(kybdat any, sender int) bool {
  return (*((*(kybdat.(*clientdss.PartialSig))).Partial)).I == sender }
