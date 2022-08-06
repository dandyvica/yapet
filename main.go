// Yet Another Personal Encryption Tool
// Simple yet effective command line tool to encrypt files.
// Shamelessly inspired from: https://levelup.gitconnected.com/a-short-guide-to-encryption-using-go-da97c928259f
package main

import (
	"fmt"
	"os"
)

func main() {
	// read command line arguments
	ctx, err := GetContext(os.Args[0], os.Args[1:])
	//fmt.Printf("%+v\n", ctx)
	CheckError(err)

	// encrypt or decrypt file
	if ctx.encrypt {
		err = ctx.EncryptFile()
		CheckError(err)
		fmt.Printf("%s successfully encrypted as %s\n", ctx.plaintextFile, ctx.ciphertextFile)
	} else if ctx.decrypt {
		err = ctx.DecryptFile()
		CheckError(err)		
		fmt.Printf("%s successfully decrypted as %s\n", ctx.ciphertextFile, ctx.plaintextFile)
	}

	// delete source file if any
	ctx.DeleteFileIfAsked()
}
