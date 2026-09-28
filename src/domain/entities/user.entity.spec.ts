import { InvalidUserError, WeakPasswordError } from "@domain/errors/auth.errors";
import { normalizeEmail } from "@domain/value-objects/email.value-object";
import { assertPasswordPolicy } from "@domain/value-objects/password-policy";
import { RefreshToken } from "./refresh-token.entity";
import { User } from "./user.entity";

const NOW = new Date("2026-09-27T12:00:00.000Z");

describe("User", () => {
  it("normaliza email, deduplica e ordena roles", () => {
    const user = User.create({
      email: "  Ana@Example.COM ",
      passwordHash: "h",
      roles: ["operator", "admin", "operator"],
      now: NOW,
    });

    expect(user.email).toBe("ana@example.com");
    expect(user.roles).toEqual(["admin", "operator"]);
    expect(user.active).toBe(true);
    expect(user.hasAnyRole(["admin"])).toBe(true);
  });

  it.each([[[]], [["root"]]])("rejeita roles %p", (roles) => {
    expect(() => User.create({ email: "a@b.co", passwordHash: "h", roles, now: NOW })).toThrow(
      InvalidUserError,
    );
  });

  it.each(["sem-arroba", "a@b", "a b@c.com", `${"x".repeat(250)}@b.co`])("rejeita email %p", (email) => {
    expect(() => normalizeEmail(email)).toThrow(InvalidUserError);
  });

  it.each([["curta", "x".repeat(11)], ["longa", "x".repeat(129)]])("rejeita senha %s", (_l, pwd) => {
    expect(() => { assertPasswordPolicy(pwd); }).toThrow(WeakPasswordError);
  });

  it("aceita senha de 12 caracteres sem regra de composicao", () => {
    expect(() => { assertPasswordPolicy("aaaaaaaaaaaa"); }).not.toThrow();
  });
});

describe("RefreshToken", () => {
  it("expira em now + ttl e nasce ativo", () => {
    const token = RefreshToken.issue({
      userId: "u",
      familyId: "f",
      tokenHash: "h",
      now: NOW,
      ttlSeconds: 60,
    });

    expect(token.isRevoked()).toBe(false);
    expect(token.isExpired(new Date(NOW.getTime() + 59_000))).toBe(false);
    expect(token.isExpired(new Date(NOW.getTime() + 60_000))).toBe(true);
  });
});
