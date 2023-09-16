package main

import (
	ecdsa "github.com/jo-makar/ecdsa-tools"

	"fmt"
)

func main() {
	privkey, err := ecdsa.NewPrivKeyOpenSSL("prime256v1")
	if err != nil {
		panic(err)
	}

	// FIXME STOPPED
	fmt.Printf("%v\n", privkey)
}
