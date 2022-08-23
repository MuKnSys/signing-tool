// TODO must keep trying to generate DistKeyShares until finding special one
// that is easy to verify on-chain. E.g. see genDistSecret() at:
// https://github.com/smartcontractkit/chainlink/blob/develop/core/services/signatures/ethdss/ethdss_test.go

package main

func init() {
  register_protocol(protocol{code: pc_dss}) }
