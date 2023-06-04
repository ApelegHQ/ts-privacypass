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

import { btoau } from '../lib/base64url.js';
import g from '../lib/global.js';
import textEncoder from '../lib/textEncoder.js';

const produceTokenChallenge = (
	tokenType: number,
	issuer: string,
	origin: string,
	redemptionContext?: ArrayBuffer,
): [Uint8Array, string] => {
	/*
	<https://developer.apple.com/news/?id=huqjyh7k>

	struct {
		uint16_t token_type;               // 0x0002, in network-byte order
		uint16_t issuer_name_length;       // Issuer name length, in network-byte order
		char issuer_name[];                // Hostname of the token issuer
		uint8_t redemption_context_length; // Redemption context length (0 or 32)
		uint8_t redemption_context[];      // Redemption context, either 0 or 32 bytes
		uint16_t origin_info_length;       // Origin info length, in network-byte order
		char origin_info[];                // Hostname of your server
		} TokenChallenge; 

	*/

	if (redemptionContext) {
		if (
			redemptionContext.byteLength !== 0 &&
			redemptionContext.byteLength !== 32
		) {
			throw new RangeError('Invalid redemption context length');
		}
	}

	const redemptionContextLength = redemptionContext?.byteLength ?? 32;

	const issuerBuf = textEncoder.encode(issuer);
	const originBuf = textEncoder.encode(origin);

	const challenge = new Uint8Array(
		2 +
			2 +
			issuerBuf.byteLength +
			1 +
			redemptionContextLength +
			2 +
			originBuf.byteLength,
	);

	// token_type
	challenge[0] = (tokenType >> 8) & 0xff;
	challenge[1] = (tokenType >> 0) & 0xff;
	// issuer_name_length
	challenge[2] = (issuerBuf.byteLength >> 8) & 0xff;
	challenge[3] = (issuerBuf.byteLength >> 0) & 0xff;
	// issuer_name
	challenge.set(issuerBuf, 4);
	// redemption_context_length
	challenge[2 + 2 + issuerBuf.byteLength] = redemptionContextLength;
	// redemption_context
	if (redemptionContext) {
		challenge.set(
			new Uint8Array(redemptionContext),
			2 + 2 + issuerBuf.byteLength + 1,
		);
	} else {
		g.crypto.getRandomValues(
			challenge.subarray(
				2 + 2 + issuerBuf.byteLength + 1,
				2 + 2 + issuerBuf.byteLength + 1 + 32,
			),
		);
	}
	// origin_info_length
	challenge[2 + 2 + issuerBuf.byteLength + 1 + redemptionContextLength] =
		(originBuf.byteLength >> 8) & 0xff;
	challenge[2 + 2 + issuerBuf.byteLength + 1 + redemptionContextLength + 1] =
		(originBuf.byteLength >> 0) & 0xff;
	// origin_info
	challenge.set(
		originBuf,
		2 + 2 + issuerBuf.byteLength + 1 + redemptionContextLength + 2,
	);

	const challenge64 = btoau(challenge);

	return [challenge, challenge64];
};

export default produceTokenChallenge;
