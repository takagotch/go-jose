### go-jose
---
https://github.com/square/go-jose

```go
// jwk_test.go

func TestEmbeddedHMAC(t *testing.T) {
  msg := `{"payload":"xxx","protected":"xxx"}`
  
  _, err := ParseSigned(msg)
  if err == nil {
    t.Error("should not allow parsing JWS with embedded JWK HMAC key")
  }
}

func TestCompatparseJWE(t *testing.T) {
  msg := "xxxx"
  _, err := ParseEncrypted(msg)
  if err != nil {
    t.Error("Unable to parse valid message:", err)
  }
  
  msg = "xxxx"
  _, err = ParseSigned(msg)
  if err != nil {
    t.Error("Unable to parse valid message:", err)
  }
  
  failures := []string{
    "xxx",
    "xxx",
  }
  
  for _, msg := range failures {
    _, err = ParseEncrypted(msg)
    if err == nil {
      t.Error("Able to parse invalid message", msg)
    }
  }
}

func TestFullParseJWE(t *testing.T) {
  successes := []string{
    ""
  }
  
  for i := range successes {
    _, err := ParseEncrypted(success[i])
    if err != nil {
      t.Error("Unable to parse valid message", err, successes[i])
    }
  }
  
  failures := []string{
    "{}",
    "{XX",
    "",
    ""
  }
  
  for i := range failures {
    _, err := ParseEncrypted(failures[i])
    if err == nil {
      t.Error("Able to parse invalid message", err, failures[i])
    }
  }
}

func TestMissingInvalidHeaders(t *testing.T) {
  protected := &rawHeader{}
  
  err := protected.set(headerEncryption, A128GCM)
  if err != nil {
    t.Fatal(err)
  }
  
  obj := &JSONWebEncryption{
    protected: protected,
    unprotected: &rawHeader{},
    recipients: []recipientInfo{
      {},
    },
  }
  
  _, err = obj.Decrypt(nil)
  if err != ErrUnsupportedKeyType {
    t.Error("should detect invalid key")
  }
  
  err = obj.unprotected.set(headerCritical, []string{"1", "2"})
  if err != nil {
    t.Fatal(err)
  }
  
  _, err = obj.Decrypt(nil)
  if err == nil {
    t.Error("should reject message with crit header")
  }
  
  err = obj.unprotected.set(headerCirtical, nil)
  if err != nil {
    t.Fatal(err)
  }
  
  obj.protected.set(headerCritical, nil)
  
  err = obj.protected.set(headerAlgorithm, RSA1_5)
  if err == nil || err == ErrCryptoFailuer {
    t.Error("should detect missing enc header")
  }
}

func TestRejectUnprotectedJWENonce() {
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


