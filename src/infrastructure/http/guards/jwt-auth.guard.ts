import {
  type CanActivate,
  createParamDecorator,
  type ExecutionContext,
  Injectable,
  SetMetadata,
} from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import type { Request } from "express";
import type { Role } from "@domain/entities/user.entity";
import { InsufficientRoleError, InvalidAccessTokenError } from "@domain/errors/auth.errors";
import {
  JwtAccessTokenService,
  type VerifiedPrincipal,
} from "@infrastructure/crypto/jwt-access-token.service";

const REQUIRED_ROLES = "requiredRoles";

// Rota exige estas roles (qualquer uma). Sem o decorator: basta estar autenticado.
export const RequireRoles = (...roles: Role[]): MethodDecorator & ClassDecorator =>
  SetMetadata(REQUIRED_ROLES, roles);

// Principal do request fora do objeto Request: evita augmentar o tipo global
// do Express e nao depende de header (que o cliente poderia forjar).
const principals = new WeakMap<Request, VerifiedPrincipal>();

@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(
    private readonly tokens: JwtAccessTokenService,
    private readonly reflector: Reflector,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<Request>();
    const token = bearerToken(request.header("authorization"));
    if (token === undefined) throw new InvalidAccessTokenError();

    const principal = await this.tokens.verify(token);
    const required = this.reflector.getAllAndOverride<Role[] | undefined>(REQUIRED_ROLES, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (required && !required.some((role) => principal.roles.includes(role))) {
      throw new InsufficientRoleError();
    }
    principals.set(request, principal);
    return true;
  }
}

export const CurrentPrincipal = createParamDecorator(
  (_data: unknown, context: ExecutionContext): VerifiedPrincipal => {
    const principal = principals.get(context.switchToHttp().getRequest<Request>());
    if (!principal) throw new InvalidAccessTokenError();
    return principal;
  },
);

function bearerToken(header: string | undefined): string | undefined {
  if (header === undefined) return undefined;
  const [scheme, token] = header.split(" ");
  if (scheme?.toLowerCase() !== "bearer" || !token) return undefined;
  return token;
}
