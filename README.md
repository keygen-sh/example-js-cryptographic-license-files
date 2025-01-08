# Example JS Cryptographic License Files

This is an example of how to verify and decrypt [cryptographic license files](https://keygen.sh/docs/api/cryptography/#cryptographic-lic)
in a browser environment, using Ed25519 verification and AES-256-GCM encryption.

> [!WARNING]
> **This example utilizes [Web Crypto](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API).**
> You may need to enable certain flags in your browser if support has not
> landed yet, e.g. for Ed25519. For the best experience, use Firefox.

This example verifies the `aes-256-gcm+ed25519` algorithm.

## Running the example

First up, install dependencies with [`yarn`](https://yarnpkg.com):

```
yarn
```

Then run the server:

```bash
yarn start
```

You can either manually input or upload the example license file, or input your
own values.

The following will happen:

1. The license file's authenticity will be verified using Ed25519, by verifying
   its signature using the provided public key.
1. The license file will be decrypted using the license key
   as the decryption key.

If everything checks out, the page will display the decrypted contents of
the license file — the license object, with any included data. If it
fails, review the error and check your inputs.

## Questions?

Reach out at [support@keygen.sh](mailto:support@keygen.sh) if you have any
questions or concerns!
