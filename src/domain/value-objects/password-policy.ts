import { WeakPasswordError } from "@domain/errors/auth.errors";

// Politica NIST 800-63B: comprimento minimo alto, sem regras de composicao.
// O maximo evita hash de entradas gigantes (custo de CPU/memoria no argon2).
export const PASSWORD_MIN_LENGTH = 12;
export const PASSWORD_MAX_LENGTH = 128;

export function assertPasswordPolicy(plain: string): void {
  if (plain.length < PASSWORD_MIN_LENGTH || plain.length > PASSWORD_MAX_LENGTH) {
    throw new WeakPasswordError(
      `Senha deve ter entre ${PASSWORD_MIN_LENGTH} e ${PASSWORD_MAX_LENGTH} caracteres`,
    );
  }
}
