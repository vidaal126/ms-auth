import type { ConfigService } from "@nestjs/config";
import { z } from "zod";

const positiveInt = z.coerce.number().int().positive();

// PEM aceito com quebras reais ou com "\n" literal (env de uma linha).
const privateKeyPem = z
  .string()
  .transform((value) => value.replace(/\\n/g, "\n").trim())
  .pipe(
    z
      .string()
      .regex(
        /^-----BEGIN PRIVATE KEY-----[\s\S]+-----END PRIVATE KEY-----$/,
        "deve ser uma chave PKCS#8 PEM (BEGIN PRIVATE KEY)",
      ),
  );

export const envSchema = z
  .object({
    NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
    PORT: z.coerce.number().int().min(1).max(65535).default(3002),
    LOG_LEVEL: z.enum(["fatal", "error", "warn", "info", "debug", "trace"]).default("info"),

    DATABASE_URL: z.string().regex(/^postgres(ql)?:\/\//, "deve ser uma URL postgresql://"),

    // Chave RSA de assinatura (RS256): conteudo PEM ou caminho de arquivo.
    // Exatamente uma das duas.
    AUTH_PRIVATE_KEY_PEM: privateKeyPem.optional(),
    AUTH_PRIVATE_KEY_FILE: z.string().min(1).optional(),
    AUTH_ISSUER: z.string().min(1).default("ms-auth"),
    AUTH_AUDIENCE: z.string().min(1).default("ms-platform"),
    ACCESS_TOKEN_TTL_SECONDS: positiveInt.min(60).max(3_600).default(900),
    REFRESH_TOKEN_TTL_SECONDS: positiveInt.min(3_600).max(60 * 60 * 24 * 30).default(60 * 60 * 24 * 7),

    // Admin inicial (opcional): criado no boot se ainda nao existir.
    AUTH_BOOTSTRAP_ADMIN_EMAIL: z.email().optional(),
    AUTH_BOOTSTRAP_ADMIN_PASSWORD: z.string().min(12).max(128).optional(),

    THROTTLE_DEFAULT_TTL_MS: positiveInt.default(60_000),
    THROTTLE_DEFAULT_LIMIT: positiveInt.default(100),
    // Limite proprio de login/refresh (forca bruta), por IP.
    THROTTLE_LOGIN_TTL_MS: positiveInt.default(60_000),
    THROTTLE_LOGIN_LIMIT: positiveInt.default(10),

    HEALTH_CHECK_TIMEOUT_MS: positiveInt.default(1_500),
    SHUTDOWN_TIMEOUT_MS: positiveInt.default(10_000),
  })
  .superRefine((env, ctx) => {
    const keySources = [env.AUTH_PRIVATE_KEY_PEM, env.AUTH_PRIVATE_KEY_FILE].filter(
      (value) => value !== undefined,
    );
    if (keySources.length !== 1) {
      ctx.addIssue({
        code: "custom",
        path: ["AUTH_PRIVATE_KEY_PEM"],
        message: "defina exatamente um entre AUTH_PRIVATE_KEY_PEM e AUTH_PRIVATE_KEY_FILE",
      });
    }
    if ((env.AUTH_BOOTSTRAP_ADMIN_EMAIL === undefined) !== (env.AUTH_BOOTSTRAP_ADMIN_PASSWORD === undefined)) {
      ctx.addIssue({
        code: "custom",
        path: ["AUTH_BOOTSTRAP_ADMIN_EMAIL"],
        message: "AUTH_BOOTSTRAP_ADMIN_EMAIL e AUTH_BOOTSTRAP_ADMIN_PASSWORD vao juntos",
      });
    }
  });

export type Env = z.infer<typeof envSchema>;

export class InvalidEnvironmentError extends Error {}

export function validateEnv(raw: Record<string, unknown>): Env {
  const result = envSchema.safeParse(raw);
  if (!result.success) {
    throw new InvalidEnvironmentError(
      `Variaveis de ambiente invalidas:\n${z.prettifyError(result.error)}`,
    );
  }
  return result.data;
}

export function readEnv<K extends keyof Env>(config: ConfigService<Env, true>, key: K): Env[K] {
  return config.get(key, { infer: true });
}
