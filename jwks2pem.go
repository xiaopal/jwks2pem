package main

import (
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/docker/libtrust"
)

type jwkt struct {
	Kty  string            `json:"kty"`
	Keys []json.RawMessage `json:"keys"`
}

func exportJwkToPemBlock(data []byte) (*pem.Block, error) {
	jwk := map[string]json.RawMessage{}
	if err := json.Unmarshal(data, &jwk); err != nil {
		return nil, fmt.Errorf("unable to decode jwk: %s", err)
	}
	delete(jwk, "kid")
	jwkData, err := json.Marshal(jwk)
	if err != nil {
		return nil, fmt.Errorf("unable to encode json: %s", err)
	}
	key, err := libtrust.UnmarshalPublicKeyJWK(jwkData)
	if err != nil {
		return nil, fmt.Errorf("unable to decode jwk: %s", err)
	}
	return key.PEMBlock()
}

func exportJwkSetToPemBlocks(data []byte) ([]*pem.Block, error) {
	if len(data) == 0 {
		// This is okay, just return an empty slice.
		return []*pem.Block{}, nil
	}

	kt := jwkt{}
	if err := json.Unmarshal(data, &kt); err != nil {
		return nil, fmt.Errorf("unable to decode jwks/jwk: %s", err)
	}

	keySet := kt.Keys
	if len(kt.Kty) > 0 {
		keySet = []json.RawMessage{data}
	}

	blocks := make([]*pem.Block, 0, len(keySet))
	for _, key := range keySet {
		block, err := exportJwkToPemBlock(key)
		if err != nil {
			return nil, fmt.Errorf("unable to encode pem: %s", err)
		}
		blocks = append(blocks, &pem.Block{Type: block.Type, Bytes: block.Bytes})
	}
	return blocks, nil
}

func main() {
	bytes, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "reading standard input.", err)
		os.Exit(1)
		return
	}

	pemBlocks, err := exportJwkSetToPemBlocks(bytes)
	if err != nil {
		fmt.Fprintln(os.Stderr, "unable to decode public key JWKS.", err)
		os.Exit(1)
		return
	}

	for _, block := range pemBlocks {
		os.Stdout.Write(pem.EncodeToMemory(block))
	}
}
