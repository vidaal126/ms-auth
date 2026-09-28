import type { User } from "@domain/entities/user.entity";
import type { SessionTokens } from "@application/use-cases/session.use-cases";
import type { TokenPairResponseDto, UserResponseDto } from "@infrastructure/http/dto/auth.dto";

export function toTokenPairResponse(session: SessionTokens): TokenPairResponseDto {
  return {
    tokenType: "Bearer",
    accessToken: session.accessToken,
    expiresIn: session.accessTokenExpiresIn,
    refreshToken: session.refreshToken,
    refreshExpiresIn: session.refreshTokenExpiresIn,
  };
}

// passwordHash nunca sai daqui.
export function toUserResponse(user: User): UserResponseDto {
  return {
    id: user.id,
    email: user.email,
    roles: [...user.roles],
    active: user.active,
    createdAt: user.createdAt.toISOString(),
  };
}
