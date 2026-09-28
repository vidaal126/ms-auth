import { Body, Controller, Get, Header, HttpCode, HttpStatus, Inject, Post } from "@nestjs/common";
import { SkipThrottle } from "@nestjs/throttler";
import {
  LoginUseCase,
  LogoutUseCase,
  RefreshSessionUseCase,
} from "@application/use-cases/session.use-cases";
import { SIGNING_KEY, type SigningKey } from "@infrastructure/crypto/signing-key";
import { LoginDto, RefreshTokenDto, type TokenPairResponseDto } from "./dto/auth.dto";
import { toTokenPairResponse } from "./mappers/auth-response.mapper";

// Rotas publicas de sessao. O throttler "login" (limite proprio via env) vale
// so para login e refresh.
@Controller("auth")
@SkipThrottle({ login: true })
export class AuthController {
  constructor(
    private readonly login: LoginUseCase,
    private readonly refresh: RefreshSessionUseCase,
    private readonly logout: LogoutUseCase,
  ) {}

  @Post("login")
  @HttpCode(HttpStatus.OK)
  @SkipThrottle({ login: false })
  @Header("Cache-Control", "no-store")
  async signIn(@Body() dto: LoginDto): Promise<TokenPairResponseDto> {
    return toTokenPairResponse(await this.login.execute(dto));
  }

  @Post("refresh")
  @HttpCode(HttpStatus.OK)
  @SkipThrottle({ login: false })
  @Header("Cache-Control", "no-store")
  async rotate(@Body() dto: RefreshTokenDto): Promise<TokenPairResponseDto> {
    return toTokenPairResponse(await this.refresh.execute(dto.refreshToken));
  }

  @Post("logout")
  @HttpCode(HttpStatus.NO_CONTENT)
  async signOut(@Body() dto: RefreshTokenDto): Promise<void> {
    await this.logout.execute(dto.refreshToken);
  }
}

interface JwksResponse {
  readonly keys: ReadonlyArray<SigningKey["publicJwk"]>;
}

// Chave publica para o gateway validar tokens sem chamar o ms-auth a cada request.
@Controller(".well-known")
@SkipThrottle({ login: true })
export class JwksController {
  constructor(@Inject(SIGNING_KEY) private readonly key: SigningKey) {}

  @Get("jwks.json")
  @Header("Cache-Control", "public, max-age=300")
  jwks(): JwksResponse {
    return { keys: [this.key.publicJwk] };
  }
}
