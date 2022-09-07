module github.com/smartcontractkit/chainlink

go 1.18

require (
	example.com/csprng v0.0.0-00010101000000-000000000000
	github.com/btcsuite/btcd v0.22.0-beta
	github.com/ethereum/go-ethereum v1.10.18
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.7.1
	go.dedis.ch/fixbuf v1.0.3
	go.dedis.ch/kyber/v3 v3.0.13
	golang.org/x/crypto v0.0.0-20220307211146-efcb8507fb70
)

require (
	github.com/kr/pretty v0.3.0 // indirect
	github.com/rogpeppe/go-internal v1.8.0 // indirect
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	go.dedis.ch/protobuf v1.0.11 // indirect
	golang.org/x/sys v0.0.0-20220319134239-a9b59b0215f8 // indirect
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b // indirect
)

// To fix CVE: c16fb56d-9de6-4065-9fca-d2b4cfb13020
// See https://github.com/dgrijalva/jwt-go/issues/463
// If that happens to get released in a 3.X.X version, we can add a constraint to our go.mod
// for it. If its in 4.X.X, then we need all our transitive deps to upgrade to it.
replace github.com/dgrijalva/jwt-go => github.com/form3tech-oss/jwt-go v3.2.1+incompatible

// replicating the replace directive on cosmos SDK
replace github.com/gogo/protobuf => github.com/regen-network/protobuf v1.3.3-alpha.regen.1

// needed to address mismatch between cosmosSDK and hdevalence/ed25519consensus
replace filippo.io/edwards25519 => filippo.io/edwards25519 v1.0.0-beta.3

// fixes deprecation warnings and keychain undefined bugs on macOS
// See https://github.com/99designs/keyring/issues/94
replace github.com/keybase/go-keychain => github.com/99designs/go-keychain v0.0.0-20191008050251-8e49817e8af4

replace example.com/csprng => ../csprng
