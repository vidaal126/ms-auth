import { Injectable } from "@nestjs/common";
import { Prisma, type User as UserModel } from "@infrastructure/database/generated/client";
import { isRole, type Role, User } from "@domain/entities/user.entity";
import { EmailAlreadyRegisteredError } from "@domain/errors/auth.errors";
import type { IUserRepository } from "@application/ports/auth.ports";
import { PrismaService } from "@infrastructure/database/prisma/prisma.service";

@Injectable()
export class UserRepositoryPrisma implements IUserRepository {
  constructor(private readonly prisma: PrismaService) {}

  async findById(id: string): Promise<User | undefined> {
    const row = await this.prisma.user.findUnique({ where: { id } });
    return row ? toDomain(row) : undefined;
  }

  async findByEmail(email: string): Promise<User | undefined> {
    const row = await this.prisma.user.findUnique({ where: { email } });
    return row ? toDomain(row) : undefined;
  }

  async create(user: User): Promise<void> {
    try {
      await this.prisma.user.create({
        data: {
          id: user.id,
          email: user.email,
          passwordHash: user.passwordHash,
          roles: [...user.roles],
          active: user.active,
          createdAt: user.createdAt,
          updatedAt: user.updatedAt,
        },
      });
    } catch (err) {
      if (err instanceof Prisma.PrismaClientKnownRequestError && err.code === "P2002") {
        throw new EmailAlreadyRegisteredError(user.email);
      }
      throw err;
    }
  }
}

function toDomain(row: UserModel): User {
  // O CHECK do banco garante roles conhecidas; o filtro so estreita o tipo.
  const roles: Role[] = row.roles.filter(isRole);
  return User.restore({
    id: row.id,
    email: row.email,
    passwordHash: row.passwordHash,
    roles,
    active: row.active,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  });
}
