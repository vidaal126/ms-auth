import { RefreshToken } from "@domain/entities/refresh-token.entity";
import type { User } from "@domain/entities/user.entity";
import {
  InvalidCredentialsError,
  InvalidRefreshTokenError,
  RefreshTokenReuseDetectedError,
} from "@domain/errors/auth.errors";
import type {
  AccessTokenIssuer,
  Clock,
  IRefreshTokenRepository,
  IUserRepository,
  PasswordHasher,
  RefreshTokenSecrets,
} from "@application/ports/auth.ports";

export interface SessionTokens {
  readonly accessToken: string;
  readonly accessTokenExpiresIn: number;
  readonly refreshToken: string;
  readonly refreshTokenExpiresIn: number;
}

export interface SessionDependencies {
  readonly users: IUserRepository;
  readonly refreshTokens: IRefreshTokenRepository;
  readonly accessTokens: AccessTokenIssuer;
  readonly secrets: RefreshTokenSecrets;
  readonly refreshTokenTtlSeconds: number;
  readonly clock: Clock;
}

async function issueSession(
  deps: SessionDependencies,
  user: User,
  refreshToken: RefreshToken,
  refreshSecret: string,
): Promise<SessionTokens> {
  const access = await deps.accessTokens.issue({ userId: user.id, roles: user.roles });
  return {
    accessToken: access.token,
    accessTokenExpiresIn: access.expiresInSeconds,
    refreshToken: refreshSecret,
    refreshTokenExpiresIn: deps.refreshTokenTtlSeconds,
  };
}

function newRefreshToken(
  deps: SessionDependencies,
  userId: string,
  familyId: string,
  now: Date,
): { entity: RefreshToken; secret: string } {
  const secret = deps.secrets.generate();
  const entity = RefreshToken.issue({
    userId,
    familyId,
    tokenHash: secret.tokenHash,
    now,
    ttlSeconds: deps.refreshTokenTtlSeconds,
  });
  return { entity, secret: secret.token };
}

export interface LoginInput {
  readonly email: string;
  readonly password: string;
}

export class LoginUseCase {
  constructor(
    private readonly deps: SessionDependencies,
    private readonly hasher: PasswordHasher,
  ) {}

  async execute(input: LoginInput): Promise<SessionTokens> {
    const user = await this.deps.users.findByEmail(input.email.trim().toLowerCase());
    // verify roda mesmo sem usuario (hash ficticio): mesmo custo de tempo.
    const passwordMatches = await this.hasher.verify(user?.passwordHash ?? null, input.password);
    if (!user || !passwordMatches || !user.active) throw new InvalidCredentialsError();

    const now = this.deps.clock();
    const { entity, secret } = newRefreshToken(this.deps, user.id, RefreshToken.newFamilyId(), now);
    await this.deps.refreshTokens.create(entity);
    return issueSession(this.deps, user, entity, secret);
  }
}

export class RefreshSessionUseCase {
  constructor(private readonly deps: SessionDependencies) {}

  // Rotacao: cada refresh token vale uma vez. Reuso de um ja rotacionado (ou
  // corrida entre dois requests com o mesmo token) revoga a familia inteira.
  async execute(refreshToken: string): Promise<SessionTokens> {
    const now = this.deps.clock();
    const current = await this.deps.refreshTokens.findByHash(this.deps.secrets.hash(refreshToken));
    if (!current) throw new InvalidRefreshTokenError();

    if (current.isRevoked()) {
      // Ja rotacionado e apresentado de novo: vazamento. Revogado por logout
      // (ou pela revogacao da familia): so invalido.
      if (!current.wasRotated()) throw new InvalidRefreshTokenError();
      await this.deps.refreshTokens.revokeFamily(current.familyId, now);
      throw new RefreshTokenReuseDetectedError();
    }
    if (current.isExpired(now)) throw new InvalidRefreshTokenError();

    const user = await this.deps.users.findById(current.userId);
    if (!user?.active) {
      await this.deps.refreshTokens.revokeFamily(current.familyId, now);
      throw new InvalidRefreshTokenError();
    }

    const { entity, secret } = newRefreshToken(this.deps, user.id, current.familyId, now);
    const rotated = await this.deps.refreshTokens.rotate(current.id, entity, now);
    if (!rotated) {
      await this.deps.refreshTokens.revokeFamily(current.familyId, now);
      throw new RefreshTokenReuseDetectedError();
    }
    return issueSession(this.deps, user, entity, secret);
  }
}

export class LogoutUseCase {
  constructor(
    private readonly refreshTokens: IRefreshTokenRepository,
    private readonly secrets: RefreshTokenSecrets,
    private readonly clock: Clock,
  ) {}

  // Idempotente: token desconhecido ou ja revogado nao e erro.
  async execute(refreshToken: string): Promise<void> {
    const current = await this.refreshTokens.findByHash(this.secrets.hash(refreshToken));
    if (current) await this.refreshTokens.revokeFamily(current.familyId, this.clock());
  }
}
