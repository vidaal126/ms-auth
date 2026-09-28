import { EmailAlreadyRegisteredError, UserNotFoundError, WeakPasswordError } from "@domain/errors/auth.errors";
import { FakePasswordHasher, InMemoryUserRepository } from "../../test/auth.fakes";
import { BootstrapAdminUseCase, CreateUserUseCase, GetUserUseCase } from "./user.use-cases";

const NOW = new Date("2026-09-27T12:00:00.000Z");

describe("casos de uso de usuario", () => {
  let users: InMemoryUserRepository;
  let createUser: CreateUserUseCase;

  beforeEach(() => {
    users = new InMemoryUserRepository();
    createUser = new CreateUserUseCase(users, new FakePasswordHasher(), () => NOW);
  });

  it("cria usuario com a senha em hash, nunca em texto", async () => {
    const user = await createUser.execute({ email: "op@example.com", password: "senha-muito-segura", roles: ["operator"] });

    expect(user.passwordHash).toBe("hashed:senha-muito-segura");
    expect(users.rows.get(user.id)).toBe(user);
  });

  it("aplica a politica de senha antes do hash", async () => {
    await expect(
      createUser.execute({ email: "op@example.com", password: "curta", roles: ["operator"] }),
    ).rejects.toBeInstanceOf(WeakPasswordError);
  });

  it("email duplicado propaga EmailAlreadyRegisteredError", async () => {
    const input = { email: "op@example.com", password: "senha-muito-segura", roles: ["operator"] };
    await createUser.execute(input);

    await expect(createUser.execute(input)).rejects.toBeInstanceOf(EmailAlreadyRegisteredError);
  });

  it("bootstrap do admin e idempotente", async () => {
    const bootstrap = new BootstrapAdminUseCase(createUser, users);

    expect(await bootstrap.execute("Admin@Example.com", "senha-muito-segura")).toBe("created");
    expect(await bootstrap.execute("admin@example.com", "senha-muito-segura")).toBe("already_exists");
    expect([...users.rows.values()].map((u) => u.roles)).toEqual([["admin"]]);
  });

  it("buscar inexistente lanca UserNotFoundError", async () => {
    await expect(new GetUserUseCase(users).execute("x")).rejects.toBeInstanceOf(UserNotFoundError);
  });
});
