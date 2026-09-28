import type { ConfigService } from "@nestjs/config";
import { createLocalJWKSet, decodeProtectedHeader, jwtVerify } from "jose";
import { InvalidAccessTokenError } from "@domain/errors/auth.errors";
import type { Env } from "@config/env";
import { generateTestSigningPem } from "../../test/auth.fakes";
import { Argon2PasswordHasher } from "./argon2-password-hasher";
import { JwtAccessTokenService } from "./jwt-access-token.service";
import { OpaqueRefreshTokenSecrets } from "./opaque-refresh-token.secrets";
import { InvalidSigningKeyError, loadSigningKey } from "./signing-key";

const USER_ID = "11111111-1111-4111-8111-111111111111";

function configWith(values: Partial<Env>): ConfigService<Env, true> {
  const config: Pick<ConfigService<Env, true>, "get"> = {
    get: ((key: keyof Env) => values[key]),
  };
  return config as ConfigService<Env, true>;
}

describe("chave de assinatura e access token", () => {
  const pem = generateTestSigningPem();
  const config = configWith({ AUTH_ISSUER: "ms-auth", AUTH_AUDIENCE: "ms-platform", ACCESS_TOKEN_TTL_SECONDS: 900 });

  it("publica JWK RSA com kid (thumbprint) e alg RS256, sem a parte privada", async () => {
    const key = await loadSigningKey({ pem });

    expect(key.publicJwk).toMatchObject({ kty: "RSA", alg: "RS256", use: "sig" });
    expect(key.publicJwk.kid).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(key.publicJwk).not.toHaveProperty("d");
  });

  it("rejeita chave ilegivel ou RSA abaixo de 2048 bits", async () => {
    await expect(loadSigningKey({ pem: "lixo" })).rejects.toBeInstanceOf(InvalidSigningKeyError);
    await expect(loadSigningKey({ pem: generateTestSigningPem(1024) })).rejects.toBeInstanceOf(
      InvalidSigningKeyError,
    );
  });

  it("token emitido valida pelo JWKS publicado (como o gateway faz)", async () => {
    const key = await loadSigningKey({ pem });
    const service = new JwtAccessTokenService(key, config);

    const { token, expiresInSeconds } = await service.issue({ userId: USER_ID, roles: ["admin"] });
    const { payload } = await jwtVerify(token, createLocalJWKSet({ keys: [key.publicJwk] }), {
      issuer: "ms-auth",
      audience: "ms-platform",
    });

    expect(expiresInSeconds).toBe(900);
    expect(decodeProtectedHeader(token)).toMatchObject({ alg: "RS256", kid: key.publicJwk.kid });
    expect(payload).toMatchObject({ sub: USER_ID, roles: ["admin"] });
    expect(typeof payload.jti).toBe("string");
    await expect(service.verify(token)).resolves.toEqual({ userId: USER_ID, roles: ["admin"] });
  });

  it("verify rejeita token de outra chave e de outra audience", async () => {
    const service = new JwtAccessTokenService(await loadSigningKey({ pem }), config);
    const otherKey = new JwtAccessTokenService(await loadSigningKey({ pem: generateTestSigningPem() }), config);
    const otherAudience = new JwtAccessTokenService(
      await loadSigningKey({ pem }),
      configWith({ AUTH_ISSUER: "ms-auth", AUTH_AUDIENCE: "outra", ACCESS_TOKEN_TTL_SECONDS: 900 }),
    );

    const fromOtherKey = (await otherKey.issue({ userId: USER_ID, roles: ["admin"] })).token;
    const forOtherAudience = (await otherAudience.issue({ userId: USER_ID, roles: ["admin"] })).token;

    await expect(service.verify(fromOtherKey)).rejects.toBeInstanceOf(InvalidAccessTokenError);
    await expect(service.verify(forOtherAudience)).rejects.toBeInstanceOf(InvalidAccessTokenError);
    await expect(service.verify("nao.e.jwt")).rejects.toBeInstanceOf(InvalidAccessTokenError);
  });
});

describe("Argon2PasswordHasher", () => {
  const hasher = new Argon2PasswordHasher();

  it("gera argon2id verificavel e rejeita senha errada, hash invalido e usuario inexistente", async () => {
    const hash = await hasher.hash("senha-muito-segura");

    expect(hash.startsWith("$argon2id$")).toBe(true);
    await expect(hasher.verify(hash, "senha-muito-segura")).resolves.toBe(true);
    await expect(hasher.verify(hash, "outra-senha-qualquer")).resolves.toBe(false);
    await expect(hasher.verify("nao-e-hash", "x")).resolves.toBe(false);
    await expect(hasher.verify(null, "senha-muito-segura")).resolves.toBe(false);
  });
});

describe("OpaqueRefreshTokenSecrets", () => {
  it("gera token de 256 bits e guarda so o sha256 hex", () => {
    const secrets = new OpaqueRefreshTokenSecrets();
    const a = secrets.generate();
    const b = secrets.generate();

    expect(a.token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(a.tokenHash).toMatch(/^[0-9a-f]{64}$/);
    expect(a.token).not.toBe(b.token);
    expect(secrets.hash(a.token)).toBe(a.tokenHash);
  });
});
