package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"strings"

	"flag"
	"fmt"
	"io/ioutil"
	"os"
)

const Usage = `
NAME
	goget: this is a grep utility written in Go. Project repository: https://github.com/dandyvica/gogrep
	Files matching the regex (see regexp Go syntax: https://golang.org/pkg/regexp/syntax) are displayed in
	addition to matching lines, with different colors.

USAGE
	goget [OPTIONS...] PATTERN [FILE...]

OPTIONS
	-u, -url
		base url

	-b, -bounds
		bounds expressed as lower..upper

	-p, -padding
		padding value (leading 0's)
`

// this will hold all options and calculated values
type Context struct {
	plaintextFile  string            // input file name to encrypt or to decrypt
	ciphertextFile string            // file name which will be written and encrypted
	ext            string            // extension used when creating the encrypted file
	passPhrase     string            // passphrase to encrypt content
	encrypt        bool              // if set, we want to encrypt
	decrypt        bool              // if set, we want to decrypt
	hash           [sha256.Size]byte // passphrase SHA256 hash
	block          cipher.Block      // AES256 block created from key
	gcm            cipher.AEAD       // cipher mode used with AES
	deleteSource   bool              // if true, the plaintext file will be deleted
	keyFile        string            // key file content is used instead of the passphrase
}

func GetContext(progname string, args []string) (*Context, error) {
	// init struct
	var options Context

	flags := flag.NewFlagSet(progname, flag.ContinueOnError)

	flags.StringVar(&options.plaintextFile, "f", "", "input file to encrypt or to decrypt")
	flags.StringVar(&options.passPhrase, "p", "", "passphrase to encrypt or decrypt content")
	flags.StringVar(&options.ext, "x", ".crypt", "extension used when creating the encrypted file")
	flags.StringVar(&options.keyFile, "k", "", "key file content is used instead of the passphrase")

	flags.BoolVar(&options.encrypt, "e", false, "encrypt the provided file")
	flags.BoolVar(&options.decrypt, "d", false, "decrypt the provided file")
	flags.BoolVar(&options.deleteSource, "s", false, "if set, the source file will be deleted")

	// flag.Usage = func() {
	// 	fmt.Print(Usage)
	// }

	err := flags.Parse(args)
	if err != nil {
		return nil, err
	}

	// check arguments validity
	if options.plaintextFile == "" {
		return nil, ErrMsgFileIsMandatory
	}

	if options.passPhrase == "" && options.keyFile == "" {
		return nil, ErrMsgPassphraseIsMandatory
	}

	if (options.decrypt && options.encrypt) || (!options.decrypt && !options.encrypt) {
		return nil, ErrMsgEncryptOrDecrypt
	}

	// build target file name depending of whether we want to encrypt or decrypt
	// if we want to encrypt, we add the extension to the target file name
	// if we want to decrypt, we build the target file name by discarding the extension
	if options.encrypt {
		options.ciphertextFile = options.plaintextFile + options.ext
	} else {
		options.ciphertextFile = options.plaintextFile
		options.plaintextFile = strings.TrimSuffix(options.plaintextFile, options.ext)
	}

	// create a SHA256 hash of the passphrase: this will be used as the AES256 key
	// passphrase or key file is specified
	if options.keyFile != "" {
		keyData, err := ioutil.ReadFile(options.keyFile)
		if err != nil {
			ErrMsgOpeningFile.Format(err, options.keyFile)
			return nil, ErrMsgOpeningFile
		}
		options.hash = sha256.Sum256(keyData)
	} else {
		options.hash = sha256.Sum256([]byte(options.passPhrase))
	}

	// create a new AES256 cipher block
	//var err error
	options.block, err = aes.NewCipher(options.hash[:])
	if err != nil {
		ErrMsgAESBlockCreation.Format(err)
		return nil, ErrMsgAESBlockCreation
	}

	// create the Galois Counter Mode (GCM) to be use with AES
	options.gcm, err = cipher.NewGCM(options.block)
	if err != nil {
		ErrMsgGCMCreation.Format(err)
		return nil, ErrMsgGCMCreation
	}

	return &options, nil
}

// Encrypt file using passphrase
func (ctx *Context) EncryptFile() error {
	// read the whole file (up to 2GB)
	plaintext, err := ioutil.ReadFile(ctx.plaintextFile)
	if err != nil {
		ErrMsgOpeningFile.Format(err, ctx.plaintextFile)
		return ErrMsgOpeningFile
	}

	// Create a unique nonce
	nonce := make([]byte, ctx.gcm.NonceSize())
	if err != nil {
		return ErrMsgNonceCreation
	}

	// encrypt the plaintext using a single method
	ciphertext := ctx.gcm.Seal(nonce, nonce, plaintext, nil)

	// save the cipher text in a new file
	// the new file name will append a '.crypt' suffix to the input file name
	err = ioutil.WriteFile(ctx.ciphertextFile, ciphertext, 0777)
	if err != nil {
		ErrMsgWriteCiphertext.Format(err, ctx.ciphertextFile)
		return ErrMsgNonceCreation
	}

	return nil
}

// Decrypt encrypted file with passphrase
func (ctx *Context) DecryptFile() error {
	// read encrypted file in memory
	ciphertext, err := ioutil.ReadFile(ctx.ciphertextFile)
	if err != nil {
		ErrMsgOpeningFile.Format(err, ctx.ciphertextFile)
		return ErrMsgOpeningFile
	}

	// nonce is at the beginning of the encrypted file
	// real cihpertext begins after the nonce
	nonce, ciphertext := ciphertext[:ctx.gcm.NonceSize()], ciphertext[ctx.gcm.NonceSize():]

	// decrypt ciphertext
	plaintext, err := ctx.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		ErrMsgCiphertextDecryption.Format(err, ctx.plaintextFile)
		return ErrMsgCiphertextDecryption
	}

	// save the decrypted file
	err = ioutil.WriteFile(ctx.plaintextFile, plaintext, 0777)
	if err != nil {
		ErrMsgWritePlaintext.Format(err, ctx.plaintextFile)
		return ErrMsgWritePlaintext
	}

	return nil
}

// Delete plaintext or ciphertext file
func (ctx *Context) DeleteFileIfAsked() {
	if ctx.deleteSource {
		var fileToDelete string
		if ctx.encrypt {
			fileToDelete = ctx.plaintextFile
		} else {
			fileToDelete = ctx.ciphertextFile
		}

		err := os.Remove(fileToDelete)
		if err != nil {
			fmt.Printf("error <%v> when trying to delete file <%s>", err, fileToDelete)
		}
	}
}
