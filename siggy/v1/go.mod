module example.com/siggy

go 1.18

require (
	example.com/csprng v0.0.0-00010101000000-000000000000
	go.dedis.ch/kyber/v3 v3.0.13
)

require (
	go.dedis.ch/fixbuf v1.0.3 // indirect
	golang.org/x/crypto v0.0.0-20190123085648-057139ce5d2b // indirect
	golang.org/x/sys v0.0.0-20190124100055-b90733256f2e // indirect
)

replace example.com/csprng => ../csprng
