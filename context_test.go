package main

import (
	//"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetContext(t *testing.T) {
	assert := assert.New(t)

	// no file
	_, err := GetContext("yapet", []string{"-p", "myphrase"})
	assert.ErrorIs(err, ErrMsgFileIsMandatory)

	// no passphrase
	_, err = GetContext("yapet", []string{"-f", "myfile"})
	assert.ErrorIs(err, ErrMsgPassphraseIsMandatory)

	// both encrypt and decrypt options
	_, err = GetContext("yapet", []string{"-f", "myfile", "-p", "myphrase", "-e", "-d"})
	assert.ErrorIs(err, ErrMsgEncryptOrDecrypt)

	// encrypt: passphrase
	ctx, err := GetContext("yapet", []string{"-f", "lorem.txt", "-p", "myphrase", "-e", "-x", ".encrypted"})
	assert.Nil(err)
	assert.Equal(ctx.plaintextFile, "lorem.txt")
	assert.Equal(ctx.ciphertextFile, "lorem.txt.encrypted")
	assert.True(ctx.encrypt)
	assert.False(ctx.decrypt)
	assert.False(ctx.deleteSource)

	// encrypt: keyfile
	ctx, err = GetContext("yapet", []string{"-f", "lorem.txt", "-k", "./testdata/myfile.key", "-e", "-s"})
	assert.Nil(err)
	assert.Equal(ctx.keyFile, "./testdata/myfile.key")
	assert.True(ctx.deleteSource)

	// decrypt
	ctx, err = GetContext("yapet", []string{"-f", "lorem.txt.crypt", "-p", "myphrase", "-d"})
	assert.Nil(err)
	assert.Equal(ctx.plaintextFile, "lorem.txt")
	assert.Equal(ctx.ciphertextFile, "lorem.txt.crypt")
	assert.False(ctx.encrypt)
	assert.True(ctx.decrypt)
}

func TestEncryptFile(t *testing.T) {
	assert := assert.New(t)

	// file doesn't exists
	ctx, _ := GetContext("yapet", []string{"-f", "./testdata/iamnotthere.txt", "-p", "myphrase", "-e", "-x", ".encrypted"})
	err := ctx.EncryptFile()
	assert.ErrorIs(err, ErrMsgOpeningFile)

	// file exists
	ctx, _ = GetContext("yapet", []string{"-f", "./testdata/lorem.txt", "-p", "myphrase", "-e", "-x", ".encrypted"})
	err = ctx.EncryptFile()
	assert.Nil(err)
	assert.FileExists("./testdata/lorem.txt.encrypted")
}
