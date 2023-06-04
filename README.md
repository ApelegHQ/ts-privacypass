# Private Access Tokens (PATs) TypeScript Implementation

 [![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=Exact-Realty_ts-privacypass&metric=reliability_rating)](https://sonarcloud.io/summary/new_code?id=Exact-Realty_ts-privacypass)
 [![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=Exact-Realty_ts-privacypass&metric=vulnerabilities)](https://sonarcloud.io/summary/new_code?id=Exact-Realty_ts-privacypass)
 [![Bugs](https://sonarcloud.io/api/project_badges/measure?project=Exact-Realty_ts-privacypass&metric=bugs)](https://sonarcloud.io/summary/new_code?id=Exact-Realty_ts-privacypass)
 [![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=Exact-Realty_ts-privacypass&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=Exact-Realty_ts-privacypass)
 [![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=Exact-Realty_ts-privacypass&metric=sqale_rating)](https://sonarcloud.io/summary/new_code?id=Exact-Realty_ts-privacypass)
 ![NPM Downloads](https://img.shields.io/npm/dw/@exact-realty/privacy-pass?style=flat-square)

This project aims to provide a comprehensive implementation of the various
Private Access Token (PAT) TypeScript Implementation Internet Engineering Task
Force (IETF) drafts in TypeScript. PATs offer a privacy-focused and efficient
way to validate user authenticity without relying on CAPTCHAs or collecting
personal data.

## ✨ Features

- Complete implementation of the current PAT IETF drafts
- Seamless integration with existing web applications and APIs
- Improved user experience with no CAPTCHA challenges or data collection
- Privacy-focused approach with minimal data exchange
- Specifically, the following token types are currently supported:
  * Token type `0x0002` (Blind RSA)
  * Token type `0x5750` (Proof of Work; experimental, non-standard)
- The following token type is not currently supported:
  * Token type `0x0001` (VOPRF)

## 📦 Installation

To use the PAT TypeScript implementation in your project, install the NPM
package:

```sh
npm install "@exact-realty/private-token"
```

## 🚀 Usage

1. Import the PAT library into your project:

```js
import {
  produceBlindRsaWwwAuthenticateHeader,
  redeemPatAuthorizationHeader,
} from '@exact-realty/private-token';
```

2. Use the PAT library to generate and validate tokens:

```js
/**
 * Put method for a KV store
 * @param {ArrayBuffer} key Key
 * @param {string} value Value
 * @returns {Promise<void> | void} Response
 */
const transientStorePut = (key, value) => {
  // KV store
  // ...
};

/**
 * Retrieve method for a KV store
 * @param {ArrayBuffer} key Key
 * @returns {Promise<string> | string} Value
 */
const transientStoreGet = (key: ArrayBuffer) => {
  // KV store
  // ...
};

/**
 * Delete method for a KV store
 * @param {ArrayBuffer} key Key
 * @returns {Promise<void> | void} Response
 */
const transientStoreDelete = (key, value) => {
  // KV store
  // ...
};

/**
 * Your request handler
 * @param {Request} req Incoming request
 * @returns {Response} Response
 */
const requestHandler = async (req) => {
  // If the request has an authorization header, validate the header and, if
  // successful, return some restricted content
  if (req.headers.has('authorization')) {
    const redemptionResult = redeemPatAuthorizationHeader(
      // REQUIRED. A string containing the HTTP authorization header
      req.headers.get('authorization'),
      // REQUIRED. KV-store function. Used to retrieve issued tokens.
      transientStoreGet,
      // REQUIRED. KV-store function. Used to remove spent tokens.
      transientStoreDelete,
    );

    if (redemptionResult) {
      // The token has been 
      return new Response('Hello, World!', {
        headers: [['content-type', 'text/plain']],
      });
    }
  }

  // If no authorization header was present or validation failed, issue a
  // challenge
  const wwwAuthenticate = produceBlindRsaWwwAuthenticateHeader(
    // REQUIRED. Hostname of the issuer.
    // Example: 'demo-pat.issuer.cloudflare.com'
    'issuer',
    // REQUIRED. Hostname of your server, or empty.
    // Example: 'example.com'
    'origin',
    // REQUIRED. KV-store function. Used to remember issued challenges and
    // lookup the verification key
    transientStorePut,
    // OPTIONAL. Array buffer for the redemption context. If provided it must be
    // an `ArrayBuffer` of length 0 or 32. Defaults to a random value.
    undefined,
    // OPTIONAL. `fetch` implementation to retrieve information about the
    // issuer. Defaults to `fetch`.
    fetch,
  );

  if (!wwwAuthenticate) {
    throw new Error('Error producing blind RSA token');
  }

  return new Response(null, {
    headers: [
        ['www-authenticate', produceBlindRsaWwwAuthenticateHeader],
    ],
  });
}
```

## 🤝 Contributing

Contributions are welcome and appreciated! If you would like to contribute to
this project.

## 📄 License

This project is licensed under the ISC License. For more information, please
refer to the [LICENSE](LICENSE) file.