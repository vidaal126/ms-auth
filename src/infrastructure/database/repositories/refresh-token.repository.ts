import { Injectable } from "@nestjs/common";
import type { RefreshToken as RefreshTokenModel } from "@infrastructure/database/generated/client";
import { RefreshToken } from "@domain/entities/refresh-token.entity";
import type { IRefreshTokenRepository } from "@application/ports/auth.ports";
import { PrismaService } from "@infrastructure/database/prisma/prisma.service";

@Injectable()
export class RefreshTokenRepositoryPrisma implements IRefreshTokenRepository {
  constructor(private readonly prisma: PrismaService) {}

  async findByHash(tokenHash: string): Promise<RefreshToken | undefined> {
    const row = await this.prisma.refreshToken.findUnique({ where: { tokenHash } });
    return row ? toDomain(row) : undefined;
  }

  async create(token: RefreshToken): Promise<void> {
    await this.prisma.refreshToken.create({ data: toData(token) });
  }

  // updateMany com revokedAt null no WHERE e o compare-and-set: dois refresh
  // simultaneos com o mesmo token, so um afeta a linha.
  async rotate(currentId: string, next: RefreshToken, now: Date): Promise<boolean> {
    return this.prisma.$transaction(async (tx) => {
      const revoked = await tx.refreshToken.updateMany({
        where: { id: currentId, revokedAt: null },
        data: { revokedAt: now, replacedById: next.id },
      });
      if (revoked.count !== 1) return false;
      await tx.refreshToken.create({ data: toData(next) });
      return true;
    });
  }

  async revokeFamily(familyId: string, now: Date): Promise<void> {
    await this.prisma.refreshToken.updateMany({
      where: { familyId, revokedAt: null },
      data: { revokedAt: now },
    });
  }

  // DELETE com LIMIT via subquery: o Prisma nao limita deleteMany. O NOT EXISTS
  // mantem a familia enquanto qualquer token dela vencer depois do cutoff.
  async deleteExpiredFamilies(cutoff: Date, limit: number): Promise<number> {
    return this.prisma.$executeRaw`
      DELETE FROM "refresh_tokens"
      WHERE "id" IN (
        SELECT t."id" FROM "refresh_tokens" t
        WHERE t."expiresAt" < ${cutoff}
          AND NOT EXISTS (
            SELECT 1 FROM "refresh_tokens" f
            WHERE f."familyId" = t."familyId" AND f."expiresAt" >= ${cutoff}
          )
        LIMIT ${limit}
      )`;
  }
}

function toData(token: RefreshToken): RefreshTokenModel {
  return {
    id: token.id,
    userId: token.userId,
    familyId: token.familyId,
    tokenHash: token.tokenHash,
    expiresAt: token.expiresAt,
    createdAt: token.createdAt,
    revokedAt: token.revokedAt,
    replacedById: token.replacedById,
  };
}

function toDomain(row: RefreshTokenModel): RefreshToken {
  return RefreshToken.restore({
    id: row.id,
    userId: row.userId,
    familyId: row.familyId,
    tokenHash: row.tokenHash,
    expiresAt: row.expiresAt,
    createdAt: row.createdAt,
    revokedAt: row.revokedAt,
    replacedById: row.replacedById,
  });
}
