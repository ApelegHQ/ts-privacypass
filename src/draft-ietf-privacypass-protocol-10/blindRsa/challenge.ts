/* Copyright © 2023 Exact Realty Limited. All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

import produceTokenChallenge from '../../draft-ietf-privacypass-auth-scheme-08/challenge.js';
import g from '../../lib/global.js';

const produceBlindRsaWwwAuthenticateHeader = async (
	issuer: string,
	origin: string,
	transientStorePut: (
		key: ArrayBuffer,
		value: string,
	) => void | Promise<void>,
	redemptionContext?: ArrayBuffer,
	fetchFn = fetch,
): Promise<string | undefined> => {
	const directoryURL = new URL(
		'https://issuer.invalid./.well-known/token-issuer-directory',
	);

	directoryURL.host = issuer;

	const directoryResponse = await fetchFn(directoryURL.toString());

	if (!directoryResponse.ok) {
		return;
	}

	try {
		const directoryBody = await directoryResponse.json();

		if (!directoryBody) {
			return;
		}

		const tokenKeys = directoryBody['token-keys'];

		if (!Array.isArray(tokenKeys)) {
			return;
		}

		const tokenKey: string | undefined = tokenKeys.find(
			(k) =>
				typeof k === 'object' &&
				k['token-type'] === 2 &&
				typeof k['token-key'] === 'string' &&
				/^MIIBUjA9[A-Za-z0-9_-]+={0,2}$/.test(k['token-key']),
		)['token-key'];

		if (!tokenKey) {
			return;
		}

		const [rawChallenge, challenge] = produceTokenChallenge(
			2,
			issuer,
			origin,
			redemptionContext,
		);

		// hash challenge and store the issuerKey
		const challengeDigest = await g.crypto.subtle.digest(
			{ ['name']: 'SHA-256' },
			rawChallenge,
		);

		await transientStorePut(challengeDigest, tokenKey);

		return `PrivateToken challenge="${challenge}", token-key="${tokenKey}"`;
	} catch {
		return;
	}
};

export default produceBlindRsaWwwAuthenticateHeader;
