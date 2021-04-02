/*
 * Copyright 2020 - MATTR Limited
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import {
  generateBls12381G2KeyPair,
  blsSign,
  blsVerify,
  blsCreateProof,
  blsVerifyProof,
} from "@mattrglobal/node-bbs-signatures";

const main = async (): Promise<void> => {
  // ISSUER
  // Generate a new key pair
  const keyPair = await generateBls12381G2KeyPair();

  console.log("Key pair generated");
  console.log(`Public key base64 = ${Buffer.from(keyPair.publicKey).toString("base64")}`);

  // PROVER -> ISSUER
  // Set of messages we wish to sign
  const attributes = [
    Uint8Array.from(Buffer.from("Rachata", "utf-8")),
    Uint8Array.from(Buffer.from("Tosirisuk", "utf-8")),
    Uint8Array.from(Buffer.from("29", "utf-8")),
    Uint8Array.from(Buffer.from("Attribute 4", "utf-8")),
  ];

  console.log("Signing a attribute set of " + attributes);

  // ISSUER -> PROVER
  // Create the signature
  const signature = await blsSign({
    keyPair,
    messages: attributes,
  });

  console.log(`Output signature base64 = ${Buffer.from(signature).toString("base64")}`);

  // PROVER
  // Verify the signature
  const isVerified = await blsVerify({
    publicKey: keyPair.publicKey,
    messages: attributes,
    signature,
  });

  const isVerifiedString = JSON.stringify(isVerified);
  console.log(`Signature verified ? ${isVerifiedString}`);

  // VERIFIER sends a random "nonce" to PROVER
  const nonce = Uint8Array.from(Buffer.from("nonce", "utf-8"));

  // PROVER creates the proof -> VERIFIER
  // Derive a proof from the signature revealing the first message
  const proof = await blsCreateProof({
    signature,
    publicKey: keyPair.publicKey,
    messages: attributes,
    nonce,
    revealed: [0, 1],
  });

  console.log(`Output proof base64 = ${Buffer.from(proof).toString("base64")}`);

  //VERIFIER verifies the created proof
  const isProofVerified = await blsVerifyProof({
    proof,
    publicKey: keyPair.publicKey,
    messages: attributes.slice(0, 2),
    nonce,
  });

  const isProofVerifiedString = JSON.stringify(isProofVerified);
  console.log(`Proof verified ? ${isProofVerifiedString}`);
};

main();
