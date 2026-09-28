import { User } from "@domain/entities/user.entity";
import {
  InvalidCredentialsError,
  InvalidRefreshTokenError,
  RefreshTokenReuseDetectedError,
} from "@domain/errors/auth.errors";
import {
  FakeAccessTokenIssuer,
  FakePasswordHasher,
  InMemoryRefreshTokenRepository,
  InMemoryUserRepository,
  SequentialRefreshSecrets,
} from "../../test/auth.fakes";
import {
  LoginUseCase,
  LogoutUseCase,
  RefreshSessionUseCase,
  type SessionDependencies,
  type SessionTokens,
} from "./session.use-cases";

const T0 = new Date("2026-09-27T12:00:00.000Z");

describe("sessao: login, refresh e logout", () => {
  let users: InMemoryUserRepository;
  let refreshTokens: InMemoryRefreshTokenRepository;
  let hasher: FakePasswordHasher;
  let accessTokens: FakeAccessTokenIssuer;
  let now: Date;
  let deps: SessionDependencies;
  let user: User;

  beforeEach(async () => {
    users = new InMemoryUserRepository();
    refreshTokens = new InMemoryRefreshTokenRepository();
    hasher = new FakePasswordHasher();
    accessTokens = new FakeAccessTokenIssuer();
    now = T0;
    deps = {
      users,
      refreshTokens,
      accessTokens,
      secrets: new SequentialRefreshSecrets(),
      refreshTokenTtlSeconds: 3_600,
      clock: () => now,
    };
    user = User.create({
      email: "ana@example.com",
      passwordHash: await hasher.hash("senha-muito-segura"),
      roles: ["operator"],
      now: T0,
    });
    await users.create(user);
  });

  const login = (email = "ana@example.com", password = "senha-muito-segura"): Promise<SessionTokens> =>
    new LoginUseCase(deps, hasher).execute({ email, password });

  it("login valido emite access token com sub e roles e um refresh token", async () => {
    const session = await login(" ANA@example.com ");

    expect(session).toMatchObject({ accessToken: "access-1", refreshToken: "refresh-1", refreshTokenExpiresIn: 3_600 });
    expect(accessTokens.issued).toEqual([{ userId: user.id, roles: ["operator"] }]);
    expect(refreshTokens.rows.size).toBe(1);
  });

  it("senha errada e email inexistente dao o mesmo erro; inexistente ainda roda o verify", async () => {
    await expect(login("ana@example.com", "errada-errada")).rejects.toBeInstanceOf(InvalidCredentialsError);
    await expect(login("ninguem@example.com")).rejects.toBeInstanceOf(InvalidCredentialsError);
    expect(hasher.dummyVerifications).toBe(1);
  });

  it("refresh rotaciona: o token antigo fica revogado e o novo funciona", async () => {
    const first = await login();
    const refresh = new RefreshSessionUseCase(deps);

    const second = await refresh.execute(first.refreshToken);
    const third = await refresh.execute(second.refreshToken);

    expect(third.refreshToken).toBe("refresh-3");
    const tokens = [...refreshTokens.rows.values()];
    expect(tokens.filter((t) => t.isRevoked())).toHaveLength(2);
    expect(new Set(tokens.map((t) => t.familyId)).size).toBe(1);
  });

  it("reuso de token rotacionado revoga a familia inteira", async () => {
    const first = await login();
    const refresh = new RefreshSessionUseCase(deps);
    const second = await refresh.execute(first.refreshToken);

    await expect(refresh.execute(first.refreshToken)).rejects.toBeInstanceOf(RefreshTokenReuseDetectedError);
    await expect(refresh.execute(second.refreshToken)).rejects.toBeInstanceOf(RefreshTokenReuseDetectedError);
    const familyId = [...refreshTokens.rows.values()][0]?.familyId ?? "";
    expect(refreshTokens.activeInFamily(familyId)).toBe(0);
  });

  it("corrida perdida no compare-and-set e tratada como reuso", async () => {
    const first = await login();
    refreshTokens.loseNextRotation = true;

    await expect(new RefreshSessionUseCase(deps).execute(first.refreshToken)).rejects.toBeInstanceOf(
      RefreshTokenReuseDetectedError,
    );
  });

  it("refresh expirado ou desconhecido e rejeitado", async () => {
    const first = await login();
    now = new Date(T0.getTime() + 3_600_000);

    await expect(new RefreshSessionUseCase(deps).execute(first.refreshToken)).rejects.toBeInstanceOf(
      InvalidRefreshTokenError,
    );
    await expect(new RefreshSessionUseCase(deps).execute("nunca-emitido")).rejects.toBeInstanceOf(
      InvalidRefreshTokenError,
    );
  });

  it("logout revoga a familia e e idempotente", async () => {
    const first = await login();
    const logout = new LogoutUseCase(refreshTokens, deps.secrets, () => now);

    await logout.execute(first.refreshToken);
    await logout.execute(first.refreshToken);
    await logout.execute("desconhecido");

    await expect(new RefreshSessionUseCase(deps).execute(first.refreshToken)).rejects.toBeInstanceOf(
      RefreshTokenReuseDetectedError,
    );
  });
});
