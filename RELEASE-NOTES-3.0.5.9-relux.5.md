# jcardsim 3.0.5.9-relux.5

Coordinate `works.relux:jcardsim:3.0.5.9-relux.5`.

ECDH and ECDSA public-key initialization reject malformed encodings, infinity
and public points outside the selected curve with `CryptoException.ILLEGAL_VALUE`.
Validation covers prime and binary fields. `ECPublicKey.setW` retains its existing
storage behavior. Failed ECDH validation leaves the output span untouched.

Run `mvn -q test` and `mvn -q install` with the documented Java Card SDK setup.
