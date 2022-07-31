// all error messages and erro exit codes defined here.
// unfortunately, Go doesn't support const structs
package main

import (
	"fmt"
	"os"
)

const ()

var (
	ErrMsgFileIsMandatory       = NewCustomError(1, "option '-f' is mandatory")
	ErrMsgPassphraseIsMandatory = NewCustomError(2, "either passphrase (-p) or keyfile (-k) is mandatory")
	ErrMsgEncryptOrDecrypt      = NewCustomError(3, "you need to chose: either encrypt or decrypt")
	ErrMsgAESBlockCreation      = NewCustomError(4, "error <%v> creating AES block from provided passphrase")
	ErrMsgGCMCreation           = NewCustomError(5, "error <%v> creating GCM mode")
	ErrMsgOpeningFile           = NewCustomError(6, "error <%v> opening file <%s>")
	ErrMsgNonceCreation         = NewCustomError(7, "error <%v> creating the nonce")
	ErrMsgWriteCiphertext       = NewCustomError(8, "error <%v> writing the encrypted file <%s>")
	ErrMsgOpenCiphertext        = NewCustomError(9, "error <%v> opening encrypted file <%s>")
	ErrMsgCiphertextDecryption  = NewCustomError(10, "|error <%v> decrypting encrypted file <%s>")
	ErrMsgWritePlaintext        = NewCustomError(11, "|error <%v> writing plaintetxt into file <%s>")
)

type CustomError struct {
	msg  string // message displayed
	code int    // exit code used to terminate the process
	ctx  string // formatted message containing details about the error
}

// format the CustomError message context using values
func (cerr *CustomError) Format(err error, values ...string) {
	cerr.ctx = fmt.Sprintf(cerr.msg, err, values)
}

func NewCustomError(code int, msg string) CustomError {
	return CustomError{msg: msg, code: code}
}

func (e CustomError) Error() string {
	return e.msg
}

func CheckError(err error) {
	if err != nil {
		customError := err.(CustomError)
		fmt.Println(customError.ctx)
		os.Exit(customError.code)
	}
}
