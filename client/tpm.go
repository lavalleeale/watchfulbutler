package main

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"io"
	"reflect"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

// generateQuote generates a quote from the TPM
func generateQuote(rwc io.ReadWriteCloser, aikHandle *tpmutil.Handle, nonce []byte, pcrSelection tpm2.PCRSelection) ([]byte, []byte, error) {
	quote, signature, err := tpm2.Quote(rwc, *aikHandle, "", "", nonce, pcrSelection, tpm2.AlgNull)
	if err != nil {
		return nil, nil, err
	}

	return quote, signature.RSA.Signature, nil
}

// verifyQuote verifies a quote from the TPM
func verifyQuote(pub *rsa.PublicKey, quote []byte, signature []byte, pcrSelection tpm2.PCRSelection, nonce []byte) error {
	// Hash the PCR values and nonce as per TPM spec
	hash := sha256.New()
	hash.Write(quote)

	// Verify the signature
	err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, hash.Sum(nil), signature)
	if err != nil {
		return err
	}

	data, err := tpm2.DecodeAttestationData(quote)
	if err != nil {
		return err
	}

	// verify nonce
	if !bytes.Equal(data.ExtraData, nonce) {
		return fmt.Errorf("nonce mismatch")
	}

	// verify PCR selection
	if data.AttestedQuoteInfo.PCRSelection.Hash != pcrSelection.Hash ||
		!reflect.DeepEqual(data.AttestedQuoteInfo.PCRSelection.PCRs, pcrSelection.PCRs) {
		return fmt.Errorf("PCR selection mismatch")
	}

	return nil
}

// createKey creates a new RSA key in the TPM
func createKey(rwc io.ReadWriteCloser) (*tpmutil.Handle, *rsa.PublicKey, error) {
	handle, key, err := tpm2.CreatePrimary(rwc, tpm2.HandleOwner, tpm2.PCRSelection{}, "", "", tpm2.Public{
		Type:       tpm2.AlgRSA,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagSignerDefault,
		RSAParameters: &tpm2.RSAParams{
			Sign: &tpm2.SigScheme{
				Alg:  tpm2.AlgRSASSA,
				Hash: tpm2.AlgSHA256,
			},
			KeyBits: 2048,
		},
	})
	if err != nil {
		return nil, nil, err
	}
	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("public key is not RSA")
	}
	return &handle, rsaKey, nil
}
