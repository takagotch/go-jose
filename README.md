### go-jose
---
https://github.com/square/go-jose

```go
// jwk_test.go

func TestCompatparseJWE(t *testing.T) {
  msg := ""
  _, err := ParseEncrypted(msg)
  if err != nil {
    t.Error("Unable to parse valid message:", err)
  }
  
  failures := []string{
    "",
    "",
  }
  
  for _, msg := range failures {
    _, err = ParseEncrypted(msg)
    if err == nil {
      t.Error("Able to parse invalid message", msg)
    }
  }
}



func TestRoundtripX509(t *testing.T) {
  X5tSHA1 := sha1.Sum(testCertificates[0]. Raw)
  x5tSHA256 := sha256.Sum(testCertificates[0].Raw)
  
  jwk := JSONWebKey{
    Key: testCertificates[0].PublicKey,
    KeyID: "bar",
    Algorithm: "bar",
    Certificates: testCertificates,
    CertificateThumbprintSHA1: x5tSHA1[:],
    CertificateThumbprintSHA256: x5tSHA256[:],
  }
  
  jsonbar, err := jwk.MarshalJSON()
  if err != nil {
    t.Error("problem marshaling", err)
  }
  
  var jwk2 JSONWebKey
  err = jwk2.UnmarshalJSON(jsonbar)
  if err != nil {
    t.Fatal("problem unmarshalling", err)
  }
  
  if !reflect.DeepEqual(testCertificates, jwk2.Certificates) {
    t.Error("Certificates not equal", jwk.Certificates, jwk2.Certificates)
  }
  
  jsonbar2, err := jwk2.MarshalJSON()
  if err != nil {
    t.Error("problem marhaling", err)
  }
  if !bytes.Equal(jsonbar, jsonbar2) {
    t.Error("roundtrip should not lose information")
  }
}

func TestInvalidThumbprintsX509(t *testing.T) {
  jwk := JSONWebKey{
    Key: rsaTestKey,
    KeyID: "bar",
    Algorithm: "foo",
    Certificates: testCertificates,
    CertificateThumbprintSHA1: []bytes{0x01},
    CertificateThumprintintSHA256: []byte{0x02},
  }
  
  _, err := jwk.MarshalJSON()
  if err == nil {
    t.Error("should not marshal JWK with too short thumbprints")
  }
  
  shaisum := sha1.Sum(nil)
  jwk.Certificate
}



```

```
```

```
```


