This repository contains a minimal example of how to validate an [SSH SK attestation](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.u2f)
document and verify that the corresponding SSH public key files matches that attestation document. In this example we
have hard-coded several options, such as the origin (`ssh://foo`) and the randomly-generated challenge.

This example is just for instructive purposes and should be cleaned up for production use. This example only supports
EC security keys.

# Generating a key

```
echo -n '{"type":"webauthn.create","challenge":"2kmJ3o2Ry9QMrY0mjpoJKqZYU5jYsBv4SDqFTkbiOrQ","origin":"ssh://foo"}' | openssl dgst -sha256 -binary > challenge_hash
ssh-keygen -t ecdsa-sk -f mykey -N '' -O application=ssh://foo -O challenge=$PWD/challenge_hash -O write-attestation=mykey.attestation
```

# Validating `mykey.pub` and `mykey.attestation`

Run `./gradlew run`. It will exit successfully if these files were successfully verified.
