package main
import (
  "fmt"; "math/big"; "sync"; "errors"
  "github.com/smartcontractkit/chainlink/core/services/signatures/ethdss"
  "github.com/smartcontractkit/chainlink/core/services/signatures/ethschnorr"
  "go.dedis.ch/kyber/v3/share/dkg/rabin"
  "go.dedis.ch/kyber/v3")

/* guest index to longterm key share */
var _longterms map[int]*dkg.DistKeyShare = make(map[int]*dkg.DistKeyShare)
var _msg *big.Int
var _dss_lck *sync.Mutex = &sync.Mutex{}

const (_op_dss_partsig int = op_dkg_final + 2)

func init() {
  register_protocol(
    protocol{code:pc_dss, make_kyber_dat:make_dss_kdat, stages:dss_stages()})}

func dss_init(longterms map[int]*dkg.DistKeyShare, msg *big.Int) {
  _dss_lck.Lock(); defer _dss_lck.Unlock(); _longterms = longterms; _msg = msg;}

func _initialized() bool {
  _dss_lck.Lock(); defer _dss_lck.Unlock(); return _msg != nil }

func _assert_initialized() {
  if !_initialized() {assert_nil(errors.New("dss not yet initialized"))} }

func _longterm1(r *protocol_run) *dkg.DistKeyShare {
  _assert_initialized()
  _dss_lck.Lock(); defer _dss_lck.Unlock(); return _longterms[(*r).guest_index]}

func _msg1() *big.Int {
  _assert_initialized()
  _dss_lck.Lock(); defer _dss_lck.Unlock(); return _msg }

func dss_stages() []protocol_stage {
  var result []protocol_stage = make([]protocol_stage, 0, 20)
  result = append(result, lookup_protocol(pc_dkg).stages...)
  result = append(result,
             ps(st_init,nil,nil,nil),
             ps(st_partsig,pr_partsig,dto_to_partsig,PartSigDTO{}),
             ps(dss_st_final,nil,nil,nil))
  return result }

type kdat_args struct { /* value object */
  secret kyber.Scalar
  participants []kyber.Point
  threshold int
}
var dss_kdat_args map[any]kdat_args = make(map[any]kdat_args) /* TODO GC */
var dss_kdat_lck *sync.Mutex = &sync.Mutex{}
var dss_kdats map[*protocol_run]*clientdss.DSS =
  make(map[*protocol_run]*clientdss.DSS)
func dss_kdat(r *protocol_run) *clientdss.DSS {
  dss_kdat_lck.Lock(); defer dss_kdat_lck.Unlock()
  return dss_kdats[r] }

func make_dss_kdat(g guest, members []member, threshold int) (any, error) {
  var (result any; e error)
  result, e = make_dkg_kdat(g, members, threshold); if e != nil {return nil, e}
  dss_kdat_lck.Lock(); defer dss_kdat_lck.Unlock()
  dss_kdat_args[result] = kdat_args{secret: g.sec,
                                    participants: member_pubs(members),
                                    threshold: threshold}
  return result, nil }

func st_init(r *protocol_run) {
  var (gen *dkg.DistKeyGenerator;random *dkg.DistKeyShare;e error;a kdat_args)
  if !_initialized() {warn("dss not yet initialized"); abandon(r); return}
  gen = (*r).kyber_dat.(*dkg.DistKeyGenerator)
  random, e = gen.DistKeyShare(); if e != nil {abandon(r); return}
  dss_kdat_lck.Lock(); defer dss_kdat_lck.Unlock()
  a = dss_kdat_args[gen]
  dss_kdats[r], e = clientdss.NewDSS(clientdss.DSSArgs{
                      Secret: a.secret, Participants: a.participants,
                      Long: _longterm1(r), Random: random,
                      H2: gen.QUAL(), Msg: _msg1(), T: a.threshold })
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
  fmt.Println(s)
  e = clientdss.Verify(_longterm1(r).Commitments()[0], _msg1(), s)
  if e != nil {warn(e)} else {fmt.Println("verification succeeded")} }
