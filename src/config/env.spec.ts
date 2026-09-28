import { generateTestSigningPem } from "../test/auth.fakes";
import { InvalidEnvironmentError, validateEnv } from "./env";

const base = { DATABASE_URL: "postgresql://auth:auth@localhost:5433/auth" };

describe("validateEnv", () => {
  it("aceita PEM em uma linha com \\n literal e aplica os padroes", () => {
    const inline = generateTestSigningPem().trim().replace(/\n/g, "\\n");

    const env = validateEnv({ ...base, AUTH_PRIVATE_KEY_PEM: inline });

    expect(env.AUTH_PRIVATE_KEY_PEM).toContain("\n");
    expect(env).toMatchObject({ PORT: 3002, ACCESS_TOKEN_TTL_SECONDS: 900, AUTH_AUDIENCE: "ms-platform" });
  });

  it("limpeza de refresh tokens: padroes e limites", () => {
    const env = validateEnv({ ...base, AUTH_PRIVATE_KEY_FILE: "/k.pem" });

    expect(env).toMatchObject({
      REFRESH_TOKEN_CLEANUP_INTERVAL_MS: 3_600_000,
      REFRESH_TOKEN_RETENTION_SECONDS: 86_400,
      REFRESH_TOKEN_CLEANUP_BATCH_SIZE: 1_000,
    });
    expect(() =>
      validateEnv({ ...base, AUTH_PRIVATE_KEY_FILE: "/k.pem", REFRESH_TOKEN_CLEANUP_BATCH_SIZE: "0" }),
    ).toThrow(InvalidEnvironmentError);
  });

  it("exige exatamente uma fonte de chave", () => {
    expect(() => validateEnv(base)).toThrow(InvalidEnvironmentError);
    expect(() =>
      validateEnv({ ...base, AUTH_PRIVATE_KEY_PEM: generateTestSigningPem(), AUTH_PRIVATE_KEY_FILE: "/k.pem" }),
    ).toThrow(/exatamente um/);
  });

  it("rejeita PEM que nao e PKCS#8", () => {
    expect(() =>
      validateEnv({ ...base, AUTH_PRIVATE_KEY_PEM: "-----BEGIN RSA PRIVATE KEY-----x-----END RSA PRIVATE KEY-----" }),
    ).toThrow(/PKCS#8/);
  });

  it("admin de bootstrap exige email e senha juntos", () => {
    expect(() =>
      validateEnv({ ...base, AUTH_PRIVATE_KEY_FILE: "/k.pem", AUTH_BOOTSTRAP_ADMIN_EMAIL: "a@b.co" }),
    ).toThrow(/vao juntos/);
  });
});
