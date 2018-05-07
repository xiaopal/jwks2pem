package main

import (
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/docker/libtrust"
)

type jwkSet struct {
	Keys []map[string]json.RawMessage `json:"keys"`
}

func exportJwkSetToPemBlocks(data []byte) ([]*pem.Block, error) {
	if len(data) == 0 {
		// This is okay, just return an empty slice.
		return []*pem.Block{}, nil
	}

	keySet := jwkSet{}
	if err := json.Unmarshal(data, &keySet); err != nil {
		return nil, fmt.Errorf("unable to decode jwks: %s", err)
	}

	blocks := make([]*pem.Block, 0, len(keySet.Keys))
	for _, key := range keySet.Keys {
		delete(key, "kid")
		jwkData, err := json.Marshal(key)
		if err != nil {
			return nil, fmt.Errorf("unable to encode json: %s", err)
		}
		key, err := libtrust.UnmarshalPublicKeyJWK(jwkData)
		if err != nil {
			return nil, fmt.Errorf("unable to decode jwk: %s", err)
		}
		block, err := key.PEMBlock()
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
