import { Injectable } from "@nestjs/common";
import { argon2id, hash as argon2Hash, verify as argon2Verify } from "argon2";
import type { PasswordHasher } from "@application/ports/auth.ports";

// Parametros minimos recomendados pela OWASP para argon2id (19 MiB, t=2, p=1).
const ARGON2_OPTIONS = {
  type: argon2id,
  memoryCost: 19_456,
  timeCost: 2,
  parallelism: 1,
} as const;

@Injectable()
export class Argon2PasswordHasher implements PasswordHasher {
  // Hash ficticio (calculado uma vez) para verificar quando o usuario nao
  // existe: login com email inexistente custa o mesmo que com senha errada.
  private dummyHash: Promise<string> | null = null;

  async hash(plain: string): Promise<string> {
    return argon2Hash(plain, ARGON2_OPTIONS);
  }

  async verify(hash: string | null, plain: string): Promise<boolean> {
    if (hash === null) {
      this.dummyHash ??= this.hash("dummy-password-for-timing");
      await argon2Verify(await this.dummyHash, plain);
      return false;
    }
    try {
      return await argon2Verify(hash, plain);
    } catch {
      // Hash corrompido/formato desconhecido: nunca autentica.
      return false;
    }
  }
}
