module github.com/pqabelian/pqringct

go 1.17

require (
	github.com/cryptosuite/kyber-go v0.0.2-alpha
	github.com/cryptosuite/liboqs-go v0.9.5-alpha
	github.com/cryptosuite/pqringct v0.0.0-00010101000000-000000000000
	golang.org/x/crypto v0.0.0-20210421170649-83a5a9bb288b
)

require golang.org/x/sys v0.0.0-20201119102817-f84b799fce68 // indirect

replace github.com/cryptosuite/pqringct => github.com/pqabelian/pqringct v0.0.0-20230408115445-4119dc79e1b9
