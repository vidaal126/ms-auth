import { randomUUID } from "node:crypto";
import { Inject, Injectable } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { SignJWT, jwtVerify } from "jose";
import { z } from "zod";
import { type Role, ROLES } from "@domain/entities/user.entity";
import { InvalidAccessTokenError } from "@domain/errors/auth.errors";
import type {
  AccessTokenClaims,
  AccessTokenIssuer,
  IssuedAccessToken,
} from "@application/ports/auth.ports";
import { type Env, readEnv } from "@config/env";
import { SIGNING_ALGORITHM, SIGNING_KEY, type SigningKey } from "./signing-key";

const claimsSchema = z.object({
  sub: z.uuid(),
  roles: z.array(z.enum(ROLES)).min(1),
});

export interface VerifiedPrincipal {
  readonly userId: string;
  readonly roles: readonly Role[];
}

// Emite e valida access tokens RS256 (claims: sub, roles, iss, aud, iat,
// exp, jti). A validacao local serve as rotas protegidas do proprio ms-auth;
// o gateway valida pelo JWKS publicado.
@Injectable()
export class JwtAccessTokenService implements AccessTokenIssuer {
  private readonly issuer: string;
  private readonly audience: string;
  private readonly ttlSeconds: number;

  constructor(
    @Inject(SIGNING_KEY) private readonly key: SigningKey,
    config: ConfigService<Env, true>,
  ) {
    this.issuer = readEnv(config, "AUTH_ISSUER");
    this.audience = readEnv(config, "AUTH_AUDIENCE");
    this.ttlSeconds = readEnv(config, "ACCESS_TOKEN_TTL_SECONDS");
  }

  async issue(claims: AccessTokenClaims): Promise<IssuedAccessToken> {
    const token = await new SignJWT({ roles: [...claims.roles] })
      .setProtectedHeader({ alg: SIGNING_ALGORITHM, kid: this.key.publicJwk.kid, typ: "JWT" })
      .setSubject(claims.userId)
      .setIssuer(this.issuer)
      .setAudience(this.audience)
      .setIssuedAt()
      .setExpirationTime(`${this.ttlSeconds}s`)
      .setJti(randomUUID())
      .sign(this.key.privateKey);
    return { token, expiresInSeconds: this.ttlSeconds };
  }

  async verify(token: string): Promise<VerifiedPrincipal> {
    try {
      const { payload } = await jwtVerify(token, this.key.publicKey, {
        algorithms: [SIGNING_ALGORITHM],
        issuer: this.issuer,
        audience: this.audience,
      });
      const claims = claimsSchema.parse(payload);
      return { userId: claims.sub, roles: claims.roles };
    } catch {
      throw new InvalidAccessTokenError();
    }
  }
}
