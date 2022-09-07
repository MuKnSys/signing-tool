package main
import (
  "github.com/smartcontractkit/chainlink/core/services/signatures/ethdss"
  "github.com/smartcontractkit/chainlink/core/services/signatures/ethschnorr"
  "go.dedis.ch/kyber/v3/share")

type PartSigDTO struct {
  Partial pri_share_dto
  SessionID []byte
  Signature ethschnorr.Signature
}

func partsig_to_dto(sig *clientdss.PartialSig) (PartSigDTO, error) {
  var (part_dto pri_share_dto; e error)
  part_dto, e = pri_share_to_dto(sig.Partial); if e!=nil {return PartSigDTO{},e}
  return PartSigDTO {
           Partial:part_dto, SessionID:sig.SessionID, Signature:sig.Signature},
         nil }

func dto_to_partsig(dto1 any) (any,error) {
  var (dto PartSigDTO = dto1.(PartSigDTO); e error; partial *share.PriShare)
  partial, e = dto_to_pri_share(dto.Partial); if e != nil {return nil, e}
  return &clientdss.PartialSig {
            Partial:partial, SessionID:dto.SessionID, Signature:dto.Signature},
         nil }
