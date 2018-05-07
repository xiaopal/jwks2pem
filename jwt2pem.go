package main

import (
  // "fmt"
  "strings"
  "os"
  "github.com/docker/libtrust"
)

func check(e error) {
    if e != nil {
        panic(e)
    }
}

func main() {
  keyFilename := os.Args[1:][0]
  // fmt.Println(keyFilename)
  certPath := strings.Replace(keyFilename, "key.pem", "", 1)
  targetPrivateKeyFilename := certPath + "/key.json"
  targetPublicKeyFilename  := certPath + "/public-key.json"

  key, err := libtrust.LoadKeyFile(keyFilename)
  check(err)

  err = libtrust.SaveKey(targetPrivateKeyFilename, key)
  check(err)

  err = libtrust.SavePublicKey(targetPublicKeyFilename, key.PublicKey())
  check(err)

}