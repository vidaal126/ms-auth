import { InvalidUserError } from "@domain/errors/auth.errors";

export const EMAIL_MAX_LENGTH = 254;

// Formato pragmatico (local@dominio.tld), sem tentar cobrir a RFC 5322 inteira.
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// Email normalizado (trim + minusculas): o unique do banco compara o valor
// normalizado, entao "A@x.com" e "a@x.com" sao o mesmo usuario.
export function normalizeEmail(raw: string): string {
  const email = raw.trim().toLowerCase();
  if (email.length > EMAIL_MAX_LENGTH || !EMAIL_PATTERN.test(email)) {
    throw new InvalidUserError("Email invalido");
  }
  return email;
}
