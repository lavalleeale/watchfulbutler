package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strings"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

type Luks2Dump struct {
	Keyslots map[int]struct {
		Type string `json:"type"`
	} `json:"keyslots"`
	Tokens map[int]struct {
		Type    string `json:"type"`
		Context []byte `json:"context"`
		Key     []byte `json:"key"`
	} `json:"tokens"`
}

// getLuksData gets the LUKS metadata from a disk
func getLuksData(diskLocation string) (Luks2Dump, error) {
	// Open the LUKS device
	cmd := exec.Command("cryptsetup", "luksDump", "--dump-json-metadata", diskLocation)
	output, err := cmd.Output()
	if err != nil {
		return Luks2Dump{}, fmt.Errorf("failed to run cryptsetup luksDump: %v", err)
	}

	// Parse the JSON output
	var luksDump Luks2Dump
	if err := json.Unmarshal(output, &luksDump); err != nil {
		return Luks2Dump{}, fmt.Errorf("failed to parse luksDump output: %v", err)
	}
	return luksDump, nil
}

// getFirstFreeLuksSlot finds the first free LUKS slot in a LUKS metadata dump
func getFirstFreeLuksSlot(luksDump Luks2Dump) (int, error) {
	// Find the first free slot
	for i := 0; i < 32; i++ {
		found := false
		for slot := range luksDump.Keyslots {
			if slot == i {
				found = true
				break
			}
		}
		if !found {
			return i, nil
		}
	}

	return -1, fmt.Errorf("no free LUKS slot found")
}

// addLuksKeyToDisk adds a LUKS key to a disk
func addLuksKeyToDisk(diskLocation string, keySlot int, existingPassword string, key []byte) error {
	cmd := exec.Command("cryptsetup", "luksAddKey", "--key-slot", fmt.Sprintf("%d", keySlot), diskLocation)
	cmd.Stdin = strings.NewReader(fmt.Sprintf("%s\n%s\n%s\n", existingPassword, string(key), string(key)))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add LUKS key: %v", err)
	}
	return nil
}

// createLuksToken saves a new LUKS token to a disk with a TPM context and RSA public key
func createLuksToken(diskLocation string, keySlot int, rwc io.ReadWriteCloser, handle *tpmutil.Handle, key *rsa.PublicKey) error {
	context, err := tpm2.ContextSave(rwc, *handle)
	if err != nil {
		return fmt.Errorf("failed to save context: %v", err)
	}
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %v", err)
	}
	token := map[string]interface{}{
		"type":     "watchfulButler",
		"keyslots": []string{fmt.Sprintf("%d", keySlot)},
		"context":  context,
		"key":      pubKeyBytes,
	}
	tokenData, err := json.Marshal(token)
	if err != nil {
		return fmt.Errorf("failed to marshal token data: %v", err)
	}

	cmd := exec.Command("cryptsetup", "token", "import", diskLocation)
	cmd.Stdin = bytes.NewReader(tokenData)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to import LUKS token: %v", err)
	}

	return nil
}

// writeLuksData creates a new LUKS key and associates a new token with it that contains a TPM context and RSA public key
func writeLuksData(rwc io.ReadWriteCloser, handle *tpmutil.Handle, key *rsa.PublicKey, diskLocation string) error {
	existingLuksData, err := getLuksData(diskLocation)
	if err != nil {
		return fmt.Errorf("failed to get existing LUKS data: %v", err)
	}
	// get existing password
	fmt.Print("Enter existing LUKS password: ")
	var existingPassword string
	fmt.Scanln(&existingPassword)
	targetSlot, err := getFirstFreeLuksSlot(existingLuksData)
	if err != nil {
		return fmt.Errorf("failed to find free LUKS slot: %v", err)
	}
	err = addLuksKeyToDisk(diskLocation, targetSlot, existingPassword, []byte("test-go"))
	if err != nil {
		return fmt.Errorf("failed to create LUKS key: %v", err)
	}
	err = createLuksToken(diskLocation, targetSlot, rwc, handle, key)
	if err != nil {
		return fmt.Errorf("failed to create LUKS token: %v", err)
	}
	return nil
}

// getExistingLuksData gets the TPM context and RSA public key from an existing LUKS token
func getExistingLuksData(diskLocation string, rwc io.ReadWriteCloser) (*tpmutil.Handle, *rsa.PublicKey, error) {
	luksDump, err := getLuksData(diskLocation)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get LUKS data: %v", err)
	}
	for _, value := range luksDump.Tokens {
		if value.Type == "watchfulButler" {
			// load tpm context
			handle, err := tpm2.ContextLoad(rwc, value.Context)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to load context: %v", err)
			}
			// load rsa key
			pubKey, err := x509.ParsePKIXPublicKey(value.Key)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to parse public key: %v", err)
			}
			return &handle, pubKey.(*rsa.PublicKey), nil
		}
	}
	return nil, nil, fmt.Errorf("no LUKS token found")
}
