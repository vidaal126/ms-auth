import { generateKeyPairSync } from "node:crypto";
import type { RefreshToken } from "@domain/entities/refresh-token.entity";
import { RefreshToken as RefreshTokenEntity } from "@domain/entities/refresh-token.entity";
import type { User } from "@domain/entities/user.entity";
import { EmailAlreadyRegisteredError } from "@domain/errors/auth.errors";
import type {
  AccessTokenClaims,
  AccessTokenIssuer,
  GeneratedRefreshSecret,
  IRefreshTokenRepository,
  IssuedAccessToken,
  IUserRepository,
  PasswordHasher,
  RefreshTokenSecrets,
} from "@application/ports/auth.ports";

export class InMemoryUserRepository implements IUserRepository {
  readonly rows = new Map<string, User>();

  async findById(id: string): Promise<User | undefined> {
    return this.rows.get(id);
  }

  async findByEmail(email: string): Promise<User | undefined> {
    return [...this.rows.values()].find((user) => user.email === email);
  }

  async create(user: User): Promise<void> {
    if (await this.findByEmail(user.email)) throw new EmailAlreadyRegisteredError(user.email);
    this.rows.set(user.id, user);
  }
}

export class InMemoryRefreshTokenRepository implements IRefreshTokenRepository {
  readonly rows = new Map<string, RefreshToken>();
  // Simula outro request rotacionando o mesmo token entre a leitura e o CAS.
  loseNextRotation = false;

  async findByHash(tokenHash: string): Promise<RefreshToken | undefined> {
    return [...this.rows.values()].find((token) => token.tokenHash === tokenHash);
  }

  async create(token: RefreshToken): Promise<void> {
    this.rows.set(token.id, token);
  }

  async rotate(currentId: string, next: RefreshToken, now: Date): Promise<boolean> {
    const current = this.rows.get(currentId);
    if (!current || current.isRevoked() || this.loseNextRotation) return false;
    this.rows.set(currentId, revoked(current, now, next.id));
    this.rows.set(next.id, next);
    return true;
  }

  async revokeFamily(familyId: string, now: Date): Promise<void> {
    for (const [id, token] of this.rows) {
      if (token.familyId === familyId && !token.isRevoked()) this.rows.set(id, revoked(token, now));
    }
  }

  activeInFamily(familyId: string): number {
    return [...this.rows.values()].filter((t) => t.familyId === familyId && !t.isRevoked()).length;
  }
}

function revoked(token: RefreshToken, now: Date, replacedById: string | null = null): RefreshToken {
  return RefreshTokenEntity.restore({
    id: token.id,
    userId: token.userId,
    familyId: token.familyId,
    tokenHash: token.tokenHash,
    expiresAt: token.expiresAt,
    createdAt: token.createdAt,
    revokedAt: now,
    replacedById: token.replacedById ?? replacedById,
  });
}

// "hash" reversivel e barato: os testes de use case nao testam argon2.
export class FakePasswordHasher implements PasswordHasher {
  dummyVerifications = 0;

  async hash(plain: string): Promise<string> {
    return `hashed:${plain}`;
  }

  async verify(hash: string | null, plain: string): Promise<boolean> {
    if (hash === null) {
      this.dummyVerifications += 1;
      return false;
    }
    return hash === `hashed:${plain}`;
  }
}

export class FakeAccessTokenIssuer implements AccessTokenIssuer {
  readonly issued: AccessTokenClaims[] = [];

  async issue(claims: AccessTokenClaims): Promise<IssuedAccessToken> {
    this.issued.push(claims);
    return { token: `access-${this.issued.length}`, expiresInSeconds: 900 };
  }
}

export class SequentialRefreshSecrets implements RefreshTokenSecrets {
  private counter = 0;

  generate(): GeneratedRefreshSecret {
    this.counter += 1;
    const token = `refresh-${this.counter}`;
    return { token, tokenHash: this.hash(token) };
  }

  hash(token: string): string {
    return `h(${token})`;
  }
}

export function generateTestSigningPem(modulusLength = 2048): string {
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength });
  return privateKey.export({ type: "pkcs8", format: "pem" }).toString();
}
