/* Go doesn't automatically marshal/unmarshal the structs in the kyber library
     due to their having fields whose type is some interface.
   So during transmission I map the kyber structs to more suitable ones. */
package main
import ("go.dedis.ch/kyber/v3"; "go.dedis.ch/kyber/v3/share";
        "go.dedis.ch/kyber/v3/share/dkg/rabin";
        "go.dedis.ch/kyber/v3/share/vss/rabin")

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
  dhkey, err = ed.DHKey.MarshalBinary()
  if err != nil { return DealDTO{}, err }
  return DealDTO {Index: (*d).Index,
                  EncDealDHKey: dhkey,
                  EncDealSignature: ed.Signature,
                  EncDealNonce: ed.Nonce,
                  EncDealCipher: ed.Cipher},
         nil }

func dto_to_deal(dto DealDTO) (*dkg.Deal, error) {
  var err error
  var point kyber.Point = suite.Point()
  err = point.UnmarshalBinary(dto.EncDealDHKey)
  if err != nil { return nil, err }
  return &dkg.Deal {Index: dto.Index,
                    Deal: &vss.EncryptedDeal {
                             DHKey: point,
                             Signature: dto.EncDealSignature,
                             Nonce: dto.EncDealNonce,
                             Cipher: dto.EncDealCipher}},
         nil }

type JustificationDTO struct { /* value object */
  Index uint32
  JSessionID []byte; JIndex uint32
  JDSessionID []byte
  JDSecShareI int; JDSecShareV []byte
  JDRndShareI int; JDRndShareV []byte
  JDT uint32; JDCommitments [][]byte
  JSignature []byte
}

func justification_to_dto(j *dkg.Justification) (JustificationDTO, error) {
  var (vj *vss.Justification; deal *vss.Deal;
       ss, rs *share.PriShare; ssv, rsv []byte;
       cs []kyber.Point; cbs [][]byte; c kyber.Point; i int; err error)
  vj = (*j).Justification; deal = (*vj).Deal
  ss = (*deal).SecShare; rs = (*deal).RndShare; cs = (*deal).Commitments
  ssv,err=(*ss).V.MarshalBinary(); if err != nil {return JustificationDTO{},err}
  rsv,err=(*rs).V.MarshalBinary(); if err != nil {return JustificationDTO{},err}
  cbs = make([][]byte, len(cs))
  for i, c = range cs {
    cbs[i],err=c.MarshalBinary(); if err != nil {return JustificationDTO{},err}}
  return JustificationDTO {
           Index: (*j).Index,
           JSessionID: (*vj).SessionID, JIndex: (*vj).Index,
           JDSessionID: (*deal).SessionID,
           JDSecShareI: (*ss).I, JDSecShareV: ssv,
           JDRndShareI: (*rs).I, JDRndShareV: rsv,
           JDT: (*deal).T, JDCommitments: cbs,
           JSignature: (*vj).Signature },
         nil }

func dto_to_justification(dto JustificationDTO) (*dkg.Justification, error) {
  var (secv, rndv kyber.Scalar; cs []kyber.Point; b []byte; i int; e error)
  secv = suite.Scalar(); rndv = suite.Scalar()
  e = secv.UnmarshalBinary(dto.JDSecShareV); if e != nil {return nil, e}
  e = rndv.UnmarshalBinary(dto.JDRndShareV); if e != nil {return nil, e}
  cs = make([]kyber.Point, len(dto.JDCommitments))
  for i, b = range dto.JDCommitments {
    cs[i]=suite.Point(); e=cs[i].UnmarshalBinary(b); if e!=nil{return nil,e}}
  return &dkg.Justification {
            Index: dto.Index,
            Justification:
              &vss.Justification {
                 SessionID: dto.JSessionID, Index: dto.JIndex,
                 Deal: &vss.Deal {
                          SessionID: dto.JDSessionID,
                          SecShare: &share.PriShare {I:dto.JDSecShareI, V:secv},
                          RndShare: &share.PriShare {I:dto.JDRndShareI, V:rndv},
                          T: dto.JDT, Commitments: cs },
                 Signature: dto.JSignature }},
         nil }
