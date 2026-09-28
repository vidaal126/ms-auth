import { createHash, randomBytes } from "node:crypto";
import { Injectable } from "@nestjs/common";
import type { GeneratedRefreshSecret, RefreshTokenSecrets } from "@application/ports/auth.ports";

// Refresh token opaco (256 bits aleatorios). So o sha256 vai para o banco:
// com essa entropia, hash rapido basta (nao ha dicionario a atacar).
@Injectable()
export class OpaqueRefreshTokenSecrets implements RefreshTokenSecrets {
  generate(): GeneratedRefreshSecret {
    const token = randomBytes(32).toString("base64url");
    return { token, tokenHash: this.hash(token) };
  }

  hash(token: string): string {
    return createHash("sha256").update(token).digest("hex");
  }
}
