module example.com/siggy

go 1.18

require (
	example.com/csprng v0.0.0-00010101000000-000000000000
	github.com/smartcontractkit/chainlink v0.0.0-00010101000000-000000000000
	go.dedis.ch/kyber/v3 v3.0.13
)

require (
	github.com/btcsuite/btcd v0.22.0-beta // indirect
	github.com/ethereum/go-ethereum v1.10.18 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	go.dedis.ch/fixbuf v1.0.3 // indirect
	go.dedis.ch/protobuf v1.0.11 // indirect
	golang.org/x/crypto v0.0.0-20220307211146-efcb8507fb70 // indirect
	golang.org/x/sys v0.0.0-20220319134239-a9b59b0215f8 // indirect
)

replace example.com/csprng => ../csprng

replace github.com/smartcontractkit/chainlink => ../ch

replace go.dedis.ch/kyber/v3 => ../kyber
