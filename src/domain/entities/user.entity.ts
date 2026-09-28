import { randomUUID } from "node:crypto";
import { InvalidUserError } from "@domain/errors/auth.errors";
import { normalizeEmail } from "@domain/value-objects/email.value-object";

export const ROLES = ["admin", "operator"] as const;
export type Role = (typeof ROLES)[number];

export function isRole(value: string): value is Role {
  return (ROLES as readonly string[]).includes(value);
}

export interface CreateUserProps {
  readonly email: string;
  readonly passwordHash: string;
  readonly roles: readonly string[];
  readonly now: Date;
}

export interface RestoreUserProps {
  readonly id: string;
  readonly email: string;
  readonly passwordHash: string;
  readonly roles: readonly Role[];
  readonly active: boolean;
  readonly createdAt: Date;
  readonly updatedAt: Date;
}

export class User {
  private constructor(
    readonly id: string,
    readonly email: string,
    readonly passwordHash: string,
    readonly roles: readonly Role[],
    readonly active: boolean,
    readonly createdAt: Date,
    readonly updatedAt: Date,
  ) {}

  // Recebe o hash, nunca a senha: a politica de senha e o hash acontecem
  // antes (use case + port PasswordHasher), fora da entidade.
  static create(props: CreateUserProps): User {
    return new User(
      randomUUID(),
      normalizeEmail(props.email),
      props.passwordHash,
      normalizeRoles(props.roles),
      true,
      props.now,
      props.now,
    );
  }

  static restore(props: RestoreUserProps): User {
    return new User(
      props.id,
      props.email,
      props.passwordHash,
      props.roles,
      props.active,
      props.createdAt,
      props.updatedAt,
    );
  }

  hasAnyRole(required: readonly Role[]): boolean {
    return required.some((role) => this.roles.includes(role));
  }
}

function normalizeRoles(raw: readonly string[]): Role[] {
  const unique = [...new Set(raw)];
  if (unique.length === 0) throw new InvalidUserError("Usuario precisa de ao menos uma role");
  const roles: Role[] = [];
  for (const role of unique) {
    if (!isRole(role)) throw new InvalidUserError(`Role desconhecida: ${role}`);
    roles.push(role);
  }
  return roles.sort();
}
