package main

import (
	"fmt"

	"github.com/kiwih/rsa-chat/peer"
)

func main() {

	jack, err := peer.New(nil)
	if err != nil {
		fmt.Println("Err:", err.Error())
		return
	}
	jack.ID = "jack"

	jill, err := peer.New(nil)
	if err != nil {
		fmt.Println("Err:", err.Error())
		return
	}
	jill.ID = "jill"

	jackToJillSession, err := jack.GetOutgoingCipherSessionKey(nil, jill.GetPublicKey(), jill.ID)
	if err != nil {
		fmt.Println("Err:", err.Error())
		return
	}

	if err := jill.LoadIncomingCipherSessionKey(jackToJillSession, jack.GetPublicKey(), jack.ID); err != nil {
		fmt.Println("Err:", err.Error())
		return
	}

	//jack can now talk to jill

	jillToJackSession, err := jill.GetOutgoingCipherSessionKey(nil, jack.GetPublicKey(), jack.ID)
	if err != nil {
		fmt.Println("Err:", err.Error())
		return
	}

	if err := jack.LoadIncomingCipherSessionKey(jillToJackSession, jill.GetPublicKey(), jill.ID); err != nil {
		fmt.Println("Err:", err.Error())
		return
	}

	fmt.Println("No errors")

}
