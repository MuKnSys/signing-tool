package main
import ("errors";"go.dedis.ch/kyber/v3";"go.dedis.ch/kyber/v3/share/dkg/rabin";
        "go.dedis.ch/kyber/v3/share")

type DKS = dkg.DistKeyShare
type _DKSDTO struct { Commits [][]byte; Share pri_share_dto }

func save_longterms(lts map[int]*DKS) {
  var (dto map[int]_DKSDTO; e error)
  dto, e = _lts_to_dto(lts); assert_nil(e)
  save_gob_to_temp(dto, "longterms_") }

func _lts_to_dto(lts map[int]*DKS) (map[int]_DKSDTO, error) {
  var (result map[int]_DKSDTO = make(map[int]_DKSDTO); i int; s *DKS)
  for i, s = range lts {
    var (dto _DKSDTO;e error); dto,e=_dks_to_dto(s); if e!=nil{return nil,e}
    result[i] = dto }
  return result, nil }

func _dks_to_dto(s *DKS) (_DKSDTO, error) {
  var (p pri_share_dto; e error; cs [][]byte; c kyber.Point; i int)
  cs = make([][]byte, len((*s).Commits))
  for i, c = range (*s).Commits {
    cs[i], e = c.MarshalBinary(); if e != nil {return _DKSDTO{},e} }
  p, e = pri_share_to_dto((*s).Share); if e != nil {return _DKSDTO{}, e}
  return _DKSDTO {Commits: cs, Share: p}, nil }

func _dto_to_lts(d map[int]_DKSDTO) (map[int]*DKS, error) {
  var (result map[int]*DKS=make(map[int]*DKS); dksdto _DKSDTO; i int; e error)
  for i,dksdto=range d {result[i],e=_dto_to_dks(dksdto);if e!=nil{return nil,e}}
  return result, nil }

func _dto_to_dks(dto _DKSDTO) (*DKS, error) {
  var (cs []kyber.Point; i int; b []byte; e error; s *share.PriShare)
  cs = make([]kyber.Point, len(dto.Commits))
  for i, b = range dto.Commits {
    cs[i]=suite.Point(); e=cs[i].UnmarshalBinary(b); if e!=nil {return nil,e} }
  s, e = dto_to_pri_share(dto.Share); if e!=nil {return nil,e}
  return &DKS{Commits: cs, Share: s}, nil }

/* returns a map from guest index to key share */
func load_longterms(guests map[int]guest, file string) map[int]*DKS {
  var lts map[int]*DKS = _load_longterms1(file)
  assert_nil(_verify_keys_subset(guests, lts)); return lts }

func _load_longterms1(file string) map[int]*DKS {
  var (dto map[int]_DKSDTO; e error; lts map[int]*DKS)
  load_gob(&dto, file); lts, e = _dto_to_lts(dto); assert_nil(e); return lts }

func _verify_keys_subset[Q,R any](xs map[int]Q, ys map[int]R) error {
  var (k int; ok bool)
  for k,_ = range xs {_,ok = ys[k]; if !ok {return errors.New("map is short")}}
  return nil }
