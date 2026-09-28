import type { RefreshToken } from "@domain/entities/refresh-token.entity";
import type { Role, User } from "@domain/entities/user.entity";

export const USER_REPOSITORY = Symbol("USER_REPOSITORY");
export const REFRESH_TOKEN_REPOSITORY = Symbol("REFRESH_TOKEN_REPOSITORY");
export const PASSWORD_HASHER = Symbol("PASSWORD_HASHER");
export const ACCESS_TOKEN_ISSUER = Symbol("ACCESS_TOKEN_ISSUER");
export const REFRESH_TOKEN_SECRETS = Symbol("REFRESH_TOKEN_SECRETS");

export interface IUserRepository {
  findById(id: string): Promise<User | undefined>;
  // email ja normalizado pelo chamador.
  findByEmail(email: string): Promise<User | undefined>;
  // Email duplicado: EmailAlreadyRegisteredError.
  create(user: User): Promise<void>;
}

export interface IRefreshTokenRepository {
  findByHash(tokenHash: string): Promise<RefreshToken | undefined>;
  create(token: RefreshToken): Promise<void>;
  // Compare-and-set: revoga `currentId` so se ainda estiver ativo e grava
  // `next` na mesma transacao. false = outro request rotacionou antes.
  rotate(currentId: string, next: RefreshToken, now: Date): Promise<boolean>;
  revokeFamily(familyId: string, now: Date): Promise<void>;
}

export interface PasswordHasher {
  hash(plain: string): Promise<string>;
  // hash null (usuario inexistente): compara contra um hash ficticio para o
  // tempo de resposta nao revelar se o email existe. Sempre false.
  verify(hash: string | null, plain: string): Promise<boolean>;
}

export interface AccessTokenClaims {
  readonly userId: string;
  readonly roles: readonly Role[];
}

export interface IssuedAccessToken {
  readonly token: string;
  readonly expiresInSeconds: number;
}

export interface AccessTokenIssuer {
  issue(claims: AccessTokenClaims): Promise<IssuedAccessToken>;
}

export interface GeneratedRefreshSecret {
  readonly token: string;
  readonly tokenHash: string;
}

export interface RefreshTokenSecrets {
  generate(): GeneratedRefreshSecret;
  hash(token: string): string;
}

export type Clock = () => Date;
