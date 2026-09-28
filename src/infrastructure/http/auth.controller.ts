import { Body, Controller, Get, Header, HttpCode, HttpStatus, Inject, Post } from "@nestjs/common";
import { SkipThrottle } from "@nestjs/throttler";
import {
  LoginUseCase,
  LogoutUseCase,
  RefreshSessionUseCase,
} from "@application/use-cases/session.use-cases";
import { RefreshTokenReuseDetectedError } from "@domain/errors/auth.errors";
import { SIGNING_KEY, type SigningKey } from "@infrastructure/crypto/signing-key";
import { MetricsService, type SessionEvent } from "@infrastructure/metrics/metrics.service";
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
    private readonly metrics: MetricsService,
  ) {}

  @Post("login")
  @HttpCode(HttpStatus.OK)
  @SkipThrottle({ login: false })
  @Header("Cache-Control", "no-store")
  async signIn(@Body() dto: LoginDto): Promise<TokenPairResponseDto> {
    return toTokenPairResponse(await this.measured("login", () => this.login.execute(dto)));
  }

  @Post("refresh")
  @HttpCode(HttpStatus.OK)
  @SkipThrottle({ login: false })
  @Header("Cache-Control", "no-store")
  async rotate(@Body() dto: RefreshTokenDto): Promise<TokenPairResponseDto> {
    return toTokenPairResponse(
      await this.measured("refresh", () => this.refresh.execute(dto.refreshToken)),
    );
  }

  @Post("logout")
  @HttpCode(HttpStatus.NO_CONTENT)
  async signOut(@Body() dto: RefreshTokenDto): Promise<void> {
    await this.measured("logout", () => this.logout.execute(dto.refreshToken));
  }

  private async measured<T>(event: SessionEvent, run: () => Promise<T>): Promise<T> {
    try {
      const result = await run();
      this.metrics.recordSession(event, "success");
      return result;
    } catch (err) {
      this.metrics.recordSession(
        event,
        err instanceof RefreshTokenReuseDetectedError ? "reuse_detected" : "failure",
      );
      throw err;
    }
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
