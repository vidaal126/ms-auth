import {
  AuthenticationError,
  AuthorizationError,
  EntityConflictError,
  EntityNotFoundError,
  InvariantViolationError,
} from "./domain.error";

// Mesma mensagem para email inexistente, senha errada e usuario inativo: a
// resposta nao revela quais emails existem.
export class InvalidCredentialsError extends AuthenticationError {
  constructor() {
    super("Credenciais invalidas");
  }
}

export class InvalidRefreshTokenError extends AuthenticationError {
  constructor() {
    super("Refresh token invalido ou expirado");
  }
}

// Refresh token ja rotacionado foi apresentado de novo: sinal de vazamento.
// A familia inteira e revogada e o usuario precisa logar de novo.
export class RefreshTokenReuseDetectedError extends AuthenticationError {
  constructor() {
    super("Refresh token reutilizado; sessao revogada");
  }
}

export class InvalidAccessTokenError extends AuthenticationError {
  constructor() {
    super("Token de acesso ausente, invalido ou expirado");
  }
}

export class InsufficientRoleError extends AuthorizationError {
  constructor() {
    super("Permissao insuficiente para esta operacao");
  }
}

export class EmailAlreadyRegisteredError extends EntityConflictError {
  constructor(readonly email: string) {
    super(`Email ${email} ja cadastrado`);
  }
}

export class UserNotFoundError extends EntityNotFoundError {
  constructor(readonly userId: string) {
    super(`Usuario ${userId} nao encontrado`);
  }
}

export class InvalidUserError extends InvariantViolationError {}

export class WeakPasswordError extends InvariantViolationError {}
