import { createPrivateKey, createPublicKey, type KeyObject } from "node:crypto";
import { readFileSync } from "node:fs";
import { calculateJwkThumbprint, exportJWK, type JWK } from "jose";

export const SIGNING_KEY = Symbol("SIGNING_KEY");
export const SIGNING_ALGORITHM = "RS256";
const MIN_MODULUS_BITS = 2048;

export interface SigningKey {
  readonly privateKey: KeyObject;
  readonly publicKey: KeyObject;
  // JWK publico publicado no JWKS; kid = thumbprint RFC 7638 (muda so se a
  // chave mudar, o que permite rotacao com cache no gateway).
  readonly publicJwk: JWK & { readonly kid: string };
}

export class InvalidSigningKeyError extends Error {}

export interface SigningKeySource {
  readonly pem?: string | undefined;
  readonly file?: string | undefined;
}

export async function loadSigningKey(source: SigningKeySource): Promise<SigningKey> {
  const pem = source.pem ?? readKeyFile(source.file);
  let privateKey: KeyObject;
  try {
    privateKey = createPrivateKey({ key: pem, format: "pem" });
  } catch {
    // Mensagem sem o conteudo da chave.
    throw new InvalidSigningKeyError("Chave privada de assinatura ilegivel (esperado PKCS#8 PEM)");
  }
  const details = privateKey.asymmetricKeyDetails;
  if (privateKey.asymmetricKeyType !== "rsa" || (details?.modulusLength ?? 0) < MIN_MODULUS_BITS) {
    throw new InvalidSigningKeyError(`Chave de assinatura deve ser RSA com ao menos ${MIN_MODULUS_BITS} bits`);
  }
  const publicKey = createPublicKey(privateKey);
  const jwk = await exportJWK(publicKey);
  const kid = await calculateJwkThumbprint(jwk);
  return {
    privateKey,
    publicKey,
    publicJwk: { ...jwk, kid, alg: SIGNING_ALGORITHM, use: "sig" },
  };
}

function readKeyFile(file: string | undefined): string {
  if (file === undefined) throw new InvalidSigningKeyError("Nenhuma fonte de chave de assinatura");
  try {
    return readFileSync(file, "utf8");
  } catch {
    throw new InvalidSigningKeyError(`Nao foi possivel ler a chave de assinatura em ${file}`);
  }
}
