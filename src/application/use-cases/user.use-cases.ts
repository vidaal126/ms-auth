import { User } from "@domain/entities/user.entity";
import { EmailAlreadyRegisteredError, UserNotFoundError } from "@domain/errors/auth.errors";
import { assertPasswordPolicy } from "@domain/value-objects/password-policy";
import { normalizeEmail } from "@domain/value-objects/email.value-object";
import type { Clock, IUserRepository, PasswordHasher } from "@application/ports/auth.ports";

export interface CreateUserInput {
  readonly email: string;
  readonly password: string;
  readonly roles: readonly string[];
}

export class CreateUserUseCase {
  constructor(
    private readonly users: IUserRepository,
    private readonly hasher: PasswordHasher,
    private readonly clock: Clock,
  ) {}

  // Email duplicado nao e pre-checado: o unique do banco decide e o
  // repositorio traduz para EmailAlreadyRegisteredError.
  async execute(input: CreateUserInput): Promise<User> {
    assertPasswordPolicy(input.password);
    const passwordHash = await this.hasher.hash(input.password);
    const user = User.create({
      email: input.email,
      passwordHash,
      roles: input.roles,
      now: this.clock(),
    });
    await this.users.create(user);
    return user;
  }
}

export class GetUserUseCase {
  constructor(private readonly users: IUserRepository) {}

  async execute(userId: string): Promise<User> {
    const user = await this.users.findById(userId);
    if (!user) throw new UserNotFoundError(userId);
    return user;
  }
}

export type BootstrapAdminOutcome = "created" | "already_exists";

// Primeiro admin do ambiente (vem do env). Idempotente e seguro com varias
// replicas subindo juntas: o unique do email resolve a corrida.
export class BootstrapAdminUseCase {
  constructor(private readonly createUser: CreateUserUseCase, private readonly users: IUserRepository) {}

  async execute(email: string, password: string): Promise<BootstrapAdminOutcome> {
    if (await this.users.findByEmail(normalizeEmail(email))) return "already_exists";
    try {
      await this.createUser.execute({ email, password, roles: ["admin"] });
      return "created";
    } catch (err) {
      if (err instanceof EmailAlreadyRegisteredError) return "already_exists";
      throw err;
    }
  }
}
