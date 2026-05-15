import {
  exportJWK,
  generateKeyPair,
  calculateJwkThumbprint,
  SignJWT,
} from 'jose';
import type { JWK, CryptoKey as JoseCryptoKey } from 'jose';
import { SecretConfig } from '@better-auth/core';

export const buildSecretConfig = (secret: string): SecretConfig => ({
  keys: new Map([[1, secret]]),
  currentVersion: 1,
});

let _dpopPrivateKey: JoseCryptoKey | null = null;
let _dpopPublicKeyJwk: JWK | null = null;
let _dpopJkt: string | null = null;

export async function getDpopState(): Promise<{
  privateKey: JoseCryptoKey;
  publicKeyJwk: JWK;
  jkt: string;
}> {
  if (!_dpopPrivateKey) {
    const { privateKey, publicKey } = await generateKeyPair('ES256');
    _dpopPrivateKey = privateKey;
    _dpopPublicKeyJwk = await exportJWK(publicKey);
    _dpopJkt = await calculateJwkThumbprint(_dpopPublicKeyJwk);
  }
  return {
    privateKey: _dpopPrivateKey,
    publicKeyJwk: _dpopPublicKeyJwk!,
    jkt: _dpopJkt!,
  };
}

export async function createDpopProof(
  htm: string,
  htu: string,
  nonce?: string,
  accessToken?: string,
): Promise<string> {
  const { privateKey, publicKeyJwk } = await getDpopState();
  const payload: Record<string, string> = { htm, htu };
  if (nonce) payload.nonce = nonce;
  if (accessToken) {
    const hash = await crypto.subtle.digest(
      'SHA-256',
      new TextEncoder().encode(accessToken),
    );
    payload.ath = Buffer.from(hash).toString('base64url');
  }
  return new SignJWT(payload)
    .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: publicKeyJwk })
    .setJti(crypto.randomUUID())
    .setIssuedAt()
    .sign(privateKey);
}
