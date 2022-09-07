/* Go doesn't automatically marshal/unmarshal the structs in the kyber library
     due to their having fields whose type is some interface.
   So during transmission I map the kyber structs to more suitable ones. */
package main
import ("go.dedis.ch/kyber/v3"; "go.dedis.ch/kyber/v3/share/vss/rabin";
        "go.dedis.ch/kyber/v3/share"; "go.dedis.ch/kyber/v3/share/dkg/rabin")

type DealDTO struct { /* value object */
  Index uint32
  EncDealDHKey []byte
  EncDealSignature []byte
  EncDealNonce []byte
  EncDealCipher []byte
}

func deal_to_dto(d *dkg.Deal) (DealDTO, error) {
  var ed vss.EncryptedDeal = *((*d).Deal)
  var (dhkey []byte; err error)
  dhkey, err = ed.DHKey.MarshalBinary(); if err != nil { return DealDTO{}, err }
  return DealDTO {Index: (*d).Index,
                  EncDealDHKey: dhkey,
                  EncDealSignature: ed.Signature,
                  EncDealNonce: ed.Nonce,
                  EncDealCipher: ed.Cipher},
         nil }

func dto_to_deal(dto1 any) (any, error) {
  var (dto DealDTO; err error; point kyber.Point)
  dto = dto1.(DealDTO)
  point = suite.Point()
  err = point.UnmarshalBinary(dto.EncDealDHKey); if err != nil {return nil, err}
  return &dkg.Deal {Index: dto.Index,
                    Deal: &vss.EncryptedDeal {
                             DHKey: point,
                             Signature: dto.EncDealSignature,
                             Nonce: dto.EncDealNonce,
                             Cipher: dto.EncDealCipher}},
         nil }

type pri_share_dto struct { I int; V []byte }

func pri_share_to_dto(s *share.PriShare) (pri_share_dto, error) {
  var (vb []byte; e error)
  vb, e = (*s).V.MarshalBinary(); if e != nil { return pri_share_dto{}, e }
  return pri_share_dto { I: (*s).I, V: vb }, nil }

func dto_to_pri_share(dto pri_share_dto) (*share.PriShare, error) {
  var (sec kyber.Scalar; e error)
  sec = suite.Scalar()
  e = sec.UnmarshalBinary(dto.V); if e != nil {return nil, e}
  return &share.PriShare {I: dto.I, V: sec}, nil }

type _vss_deal_dto struct {
  SessionID []byte
  SecShare, RndShare pri_share_dto
  T uint32; Commitments [][]byte
}

func _vss_deal_to_dto(deal *vss.Deal) (_vss_deal_dto, error) {
  var (sp, rp pri_share_dto; cbs [][]byte; c kyber.Point; i int; e error)
  sp,e=pri_share_to_dto((*deal).SecShare); if e!=nil{return _vss_deal_dto{},e}
  rp,e=pri_share_to_dto((*deal).RndShare); if e!=nil{return _vss_deal_dto{},e}
  cbs = make([][]byte, len((*deal).Commitments))
  for i, c = range (*deal).Commitments {
    cbs[i], e = c.MarshalBinary(); if e != nil {return _vss_deal_dto{}, e}}
  return _vss_deal_dto {
           SessionID: (*deal).SessionID,
           SecShare: sp, RndShare: rp,
           T: (*deal).T, Commitments: cbs },
         nil }

func _dto_to_vss_deal(d _vss_deal_dto) (*vss.Deal, error) {
  var (sec, rnd *share.PriShare; cs []kyber.Point; b []byte; i int; e error)
  sec, e = dto_to_pri_share(d.SecShare); if e!=nil {return nil, e}
  rnd, e = dto_to_pri_share(d.RndShare); if e!=nil {return nil, e}
  cs = make([]kyber.Point, len(d.Commitments))
  for i, b = range d.Commitments {
    cs[i]=suite.Point(); e=cs[i].UnmarshalBinary(b); if e!=nil{return nil,e}}
  return &vss.Deal {
            SessionID: d.SessionID,
            SecShare: sec, RndShare: rnd,
            T: d.T, Commitments: cs },
         nil }

type JustificationDTO struct { /* value object */
  Index uint32
  JSessionID []byte;
  JIndex uint32
  JDeal _vss_deal_dto
  JSignature []byte
}

func justification_to_dto(j *dkg.Justification) (JustificationDTO, error) {
  var (vj *vss.Justification; deal *vss.Deal; jd _vss_deal_dto; e error)
  vj = (*j).Justification; deal = (*vj).Deal
  jd, e = _vss_deal_to_dto(deal); if e != nil {return JustificationDTO{}, e}
  return JustificationDTO {
           Index: (*j).Index,
           JSessionID: (*vj).SessionID, JIndex: (*vj).Index,
           JDeal: jd,
           JSignature: (*vj).Signature },
         nil }

func dto_to_justification(dto1 any) (any, error) {
  var (dto JustificationDTO; deal *vss.Deal; e error)
  dto = dto1.(JustificationDTO)
  deal, e = _dto_to_vss_deal(dto.JDeal); if e != nil {return nil, e}
  return &dkg.Justification {
            Index: dto.Index,
            Justification:
              &vss.Justification {
                 SessionID: dto.JSessionID, Index: dto.JIndex,
                 Deal: deal,
                 Signature: dto.JSignature }},
         nil }

type CommitsDTO struct { /* value object */
  Index uint32
  Commitments [][]byte
  SessionID []byte
  Signature []byte
}

func commits_to_dto (sc *dkg.SecretCommits) (CommitsDTO, error) {
  var (i int; commitments [][]byte; p kyber.Point; e error)
  commitments = make([][]byte, len((*sc).Commitments))
  for i, p = range((*sc).Commitments) {
    commitments[i], e = p.MarshalBinary(); if e != nil {return CommitsDTO{}, e}}
  return CommitsDTO {
           Index: (*sc).Index,
           Commitments: commitments,
           SessionID: (*sc).SessionID,
           Signature: (*sc).Signature },
         nil }

func dto_to_commits(dto1 any) (any, error) {
  var (cs []kyber.Point; dto CommitsDTO; i int; e error; c []byte)
  dto = dto1.(CommitsDTO)
  cs = make([]kyber.Point, len(dto.Commitments))
  for i, c = range(dto.Commitments) {
    cs[i]=suite.Point(); e=cs[i].UnmarshalBinary(c); if e!=nil{return nil,e}}
  return &dkg.SecretCommits {
            Index: dto.Index,
            Commitments: cs,
            SessionID: dto.SessionID,
            Signature: dto.Signature },
         nil }

type ComplCommitsDTO struct { /* value object */
  Index uint32
  DealerIndex uint32
  Deal _vss_deal_dto
  Signature []byte
}

func compl_commits_to_dto(cmpl *dkg.ComplaintCommits) (ComplCommitsDTO,error) {
  var (d _vss_deal_dto; e error)
  d, e = _vss_deal_to_dto((*cmpl).Deal); if e!=nil {return ComplCommitsDTO{},e}
  return ComplCommitsDTO {
           Index: cmpl.Index,
           DealerIndex: cmpl.DealerIndex,
           Deal: d,
           Signature: cmpl.Signature },
         nil }

func dto_to_compl_commits(dto1 any) (any,error) {
  var (dto ComplCommitsDTO; d *vss.Deal; e error)
  dto = dto1.(ComplCommitsDTO)
  d, e = _dto_to_vss_deal(dto.Deal); if e != nil {return nil, e}
  return &dkg.ComplaintCommits {
            Index: dto.Index,
            DealerIndex: dto.DealerIndex,
            Deal: d,
            Signature: dto.Signature },
         nil }

type ReconsCommitsDTO struct {
  SessionID []byte
  Index uint32
  DealerIndex uint32
  Share pri_share_dto
  Signature []byte
}

func recons_commits_to_dto(r *dkg.ReconstructCommits) (ReconsCommitsDTO,error) {
  var (share pri_share_dto; e error)
  share,e=pri_share_to_dto((*r).Share); if e!=nil{return ReconsCommitsDTO{},e}
  return ReconsCommitsDTO {
           SessionID: (*r).SessionID,
           Index: (*r).Index,
           DealerIndex: (*r).DealerIndex,
           Share: share,
           Signature: (*r).Signature },
         nil }

func dto_to_recons_commits(dto1 any) (any,error) {
  var (dto ReconsCommitsDTO; share *share.PriShare; e error)
  dto = dto1.(ReconsCommitsDTO)
  share, e = dto_to_pri_share(dto.Share); if e != nil {return nil, e}
  return &dkg.ReconstructCommits {
            SessionID: dto.SessionID,
            Index: dto.Index,
            DealerIndex: dto.DealerIndex,
            Share: share,
            Signature: dto.Signature },
         nil }

