import { execFileSync } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { NestExpressApplication } from "@nestjs/platform-express";
import { PostgreSqlContainer, type StartedPostgreSqlContainer } from "@testcontainers/postgresql";
import { createRemoteJWKSet, jwtVerify } from "jose";
import { z } from "zod";
import { sampleValue } from "../../src/test/metrics.helpers";

const ADMIN_EMAIL = "admin@ms-platform.local";
const ADMIN_PASSWORD = "admin-senha-segura";

const tokenPairSchema = z.object({
  tokenType: z.literal("Bearer"),
  accessToken: z.string(),
  expiresIn: z.number(),
  refreshToken: z.string(),
  refreshExpiresIn: z.number(),
});

interface HttpResult {
  readonly status: number;
  readonly body: unknown;
  readonly headers: Headers;
}

// Postgres real + aplicacao completa (ValidationPipe, filtro, throttler).
describe("ms-auth: sessao, usuarios e JWKS (integracao)", () => {
  let postgres: StartedPostgreSqlContainer;
  let app: NestExpressApplication;
  let baseUrl: string;

  const call = async (
    method: "GET" | "POST",
    path: string,
    body?: unknown,
    token?: string,
  ): Promise<HttpResult> => {
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (token !== undefined) headers.authorization = `Bearer ${token}`;
    const response = await fetch(`${baseUrl}${path}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await response.text();
    return { status: response.status, body: text ? JSON.parse(text) : null, headers: response.headers };
  };

  const login = async (email: string, password: string): Promise<z.infer<typeof tokenPairSchema>> => {
    const result = await call("POST", "/auth/login", { email, password });
    expect(result.status).toBe(200);
    return tokenPairSchema.parse(result.body);
  };

  beforeAll(async () => {
    postgres = await new PostgreSqlContainer("postgres:16-alpine").start();
    const databaseUrl = postgres.getConnectionUri();
    execFileSync("npx", ["prisma", "migrate", "deploy"], {
      env: { ...process.env, DATABASE_URL: databaseUrl },
      stdio: "pipe",
    });

    // Chave em arquivo (como no compose). Sobrescreve AUTH_PRIVATE_KEY_FILE de
    // um .env local; o formato PEM inline e coberto no env.spec.
    const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const keyFile = join(mkdtempSync(join(tmpdir(), "ms-auth-")), "signing-key.pem");
    writeFileSync(keyFile, privateKey.export({ type: "pkcs8", format: "pem" }).toString());

    Object.assign(process.env, {
      NODE_ENV: "production",
      LOG_LEVEL: "error",
      DATABASE_URL: databaseUrl,
      AUTH_PRIVATE_KEY_FILE: keyFile,
      AUTH_BOOTSTRAP_ADMIN_EMAIL: ADMIN_EMAIL,
      AUTH_BOOTSTRAP_ADMIN_PASSWORD: ADMIN_PASSWORD,
      THROTTLE_LOGIN_LIMIT: "50",
    });

    const { NestFactory } = await import("@nestjs/core");
    const { AppModule } = await import("../../src/app.module");
    const { configureApp } = await import("../../src/app.setup");
    app = await NestFactory.create<NestExpressApplication>(AppModule, { logger: false, abortOnError: false });
    configureApp(app);
    await app.listen(0);
    baseUrl = (await app.getUrl()).replace("[::1]", "localhost");
  });

  afterAll(async () => {
    await app?.close();
    await postgres?.stop();
  });

  it("admin do bootstrap faz login; token valida pelo JWKS publicado", async () => {
    const session = await login(ADMIN_EMAIL, ADMIN_PASSWORD);

    const { payload } = await jwtVerify(
      session.accessToken,
      createRemoteJWKSet(new URL(`${baseUrl}/.well-known/jwks.json`)),
      { issuer: "ms-auth", audience: "ms-platform" },
    );
    expect(payload.roles).toEqual(["admin"]);
    expect(session.expiresIn).toBe(900);
  });

  it("credenciais erradas e email inexistente: 401 com a mesma mensagem", async () => {
    const wrong = await call("POST", "/auth/login", { email: ADMIN_EMAIL, password: "senha-errada-123" });
    const unknown = await call("POST", "/auth/login", { email: "x@y.com", password: "senha-errada-123" });
    const invalid = await call("POST", "/auth/login", { email: "nao-e-email", password: "x" });

    expect(wrong.status).toBe(401);
    expect(unknown.status).toBe(401);
    expect(unknown.body).toEqual(wrong.body);
    expect(invalid.status).toBe(400);
  });

  it("POST /users: admin cria (201), sem token 401, operator 403, duplicado 409", async () => {
    const admin = await login(ADMIN_EMAIL, ADMIN_PASSWORD);
    const operatorInput = { email: "Operador@Example.com", password: "operador-senha-1", roles: ["operator"] };

    const created = await call("POST", "/users", operatorInput, admin.accessToken);
    const anonymous = await call("POST", "/users", operatorInput);
    const duplicate = await call("POST", "/users", operatorInput, admin.accessToken);
    const operator = await login("operador@example.com", "operador-senha-1");
    const forbidden = await call(
      "POST",
      "/users",
      { email: "outro@example.com", password: "outra-senha-123", roles: ["admin"] },
      operator.accessToken,
    );

    expect(created.status).toBe(201);
    expect(created.body).toMatchObject({ email: "operador@example.com", roles: ["operator"], active: true });
    expect(created.body).not.toHaveProperty("passwordHash");
    expect(anonymous.status).toBe(401);
    expect(duplicate.status).toBe(409);
    expect(forbidden.status).toBe(403);
  });

  it("GET /users/me devolve o dono do token", async () => {
    const operator = await login("operador@example.com", "operador-senha-1");

    const me = await call("GET", "/users/me", undefined, operator.accessToken);

    expect(me.status).toBe(200);
    expect(me.body).toMatchObject({ email: "operador@example.com", roles: ["operator"] });
  });

  it("refresh rotaciona; reuso do antigo revoga a sessao inteira", async () => {
    const first = await login("operador@example.com", "operador-senha-1");

    const rotated = await call("POST", "/auth/refresh", { refreshToken: first.refreshToken });
    const second = tokenPairSchema.parse(rotated.body);
    const reused = await call("POST", "/auth/refresh", { refreshToken: first.refreshToken });
    const afterReuse = await call("POST", "/auth/refresh", { refreshToken: second.refreshToken });

    expect(rotated.status).toBe(200);
    expect(rotated.headers.get("cache-control")).toBe("no-store");
    expect(second.refreshToken).not.toBe(first.refreshToken);
    expect(reused.status).toBe(401);
    expect(afterReuse.status).toBe(401);
  });

  it("logout invalida o refresh token e e idempotente", async () => {
    const session = await login("operador@example.com", "operador-senha-1");

    const first = await call("POST", "/auth/logout", { refreshToken: session.refreshToken });
    const again = await call("POST", "/auth/logout", { refreshToken: session.refreshToken });
    const refresh = await call("POST", "/auth/refresh", { refreshToken: session.refreshToken });

    expect(first.status).toBe(204);
    expect(again.status).toBe(204);
    expect(refresh.status).toBe(401);
  });

  it("health ready com banco no ar", async () => {
    expect((await call("GET", "/health/ready")).status).toBe(200);
  });

  it("GET /metrics conta logins, falhas e reuso de refresh", async () => {
    const text = await (await fetch(`${baseUrl}/metrics`)).text();

    expect(sampleValue(text, "auth_session_events_total", { event: "login", outcome: "success" })).toBeGreaterThan(0);
    expect(sampleValue(text, "auth_session_events_total", { event: "login", outcome: "failure" })).toBe(2);
    // Reuso so do token rotacionado; o vigente (revogado junto) e o deslogado
    // contam como falha comum.
    expect(sampleValue(text, "auth_session_events_total", { event: "refresh", outcome: "reuse_detected" })).toBe(1);
    expect(sampleValue(text, "auth_session_events_total", { event: "refresh", outcome: "failure" })).toBe(2);
    expect(
      sampleValue(text, "http_request_duration_seconds_count", { method: "GET", route: "/users/me", status_code: "200" }),
    ).toBe(1);
  });

  // Roda por ultimo: esgota o balde de login de um cliente.
  it("throttler de login conta por cliente (X-Forwarded-For do gateway), nao pelo proxy", async () => {
    const loginFrom = async (clientIp: string): Promise<number> => {
      const response = await fetch(`${baseUrl}/auth/login`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-forwarded-for": clientIp },
        body: JSON.stringify({ email: "ninguem@ms-platform.local", password: "senha-errada-123" }),
      });
      await response.text();
      return response.status;
    };
    const loginLimit = Number(process.env.THROTTLE_LOGIN_LIMIT);

    for (let attempt = 0; attempt < loginLimit; attempt++) {
      expect(await loginFrom("203.0.113.10")).toBe(401);
    }
    expect(await loginFrom("203.0.113.10")).toBe(429);
    expect(await loginFrom("203.0.113.20")).toBe(401);
  });
});
