import { randomUUID } from "node:crypto";

export interface IssueRefreshTokenProps {
  readonly userId: string;
  // Sessao de origem: todas as rotacoes de um login compartilham a familia,
  // para que o reuso de qualquer token revogue a sessao inteira.
  readonly familyId: string;
  readonly tokenHash: string;
  readonly now: Date;
  readonly ttlSeconds: number;
}

export interface RestoreRefreshTokenProps {
  readonly id: string;
  readonly userId: string;
  readonly familyId: string;
  readonly tokenHash: string;
  readonly expiresAt: Date;
  readonly createdAt: Date;
  readonly revokedAt: Date | null;
  readonly replacedById: string | null;
}

// Guarda so o hash do token: vazamento do banco nao entrega sessoes validas.
export class RefreshToken {
  private constructor(
    readonly id: string,
    readonly userId: string,
    readonly familyId: string,
    readonly tokenHash: string,
    readonly expiresAt: Date,
    readonly createdAt: Date,
    readonly revokedAt: Date | null,
    // Preenchido so na rotacao: distingue "ja trocado por outro" (reuso se
    // reaparecer) de "revogado por logout/revogacao da familia".
    readonly replacedById: string | null,
  ) {}

  static issue(props: IssueRefreshTokenProps): RefreshToken {
    return new RefreshToken(
      randomUUID(),
      props.userId,
      props.familyId,
      props.tokenHash,
      new Date(props.now.getTime() + props.ttlSeconds * 1000),
      props.now,
      null,
      null,
    );
  }

  static restore(props: RestoreRefreshTokenProps): RefreshToken {
    return new RefreshToken(
      props.id,
      props.userId,
      props.familyId,
      props.tokenHash,
      props.expiresAt,
      props.createdAt,
      props.revokedAt,
      props.replacedById,
    );
  }

  static newFamilyId(): string {
    return randomUUID();
  }

  isRevoked(): boolean {
    return this.revokedAt !== null;
  }

  wasRotated(): boolean {
    return this.replacedById !== null;
  }

  isExpired(now: Date): boolean {
    return this.expiresAt.getTime() <= now.getTime();
  }
}
