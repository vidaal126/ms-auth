import { Module } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import {
  ACCESS_TOKEN_ISSUER,
  type AccessTokenIssuer,
  type IRefreshTokenRepository,
  type IUserRepository,
  PASSWORD_HASHER,
  type PasswordHasher,
  REFRESH_TOKEN_REPOSITORY,
  REFRESH_TOKEN_SECRETS,
  type RefreshTokenSecrets,
  USER_REPOSITORY,
} from "@application/ports/auth.ports";
import {
  LoginUseCase,
  LogoutUseCase,
  RefreshSessionUseCase,
  type SessionDependencies,
} from "@application/use-cases/session.use-cases";
import {
  BootstrapAdminUseCase,
  CreateUserUseCase,
  GetUserUseCase,
} from "@application/use-cases/user.use-cases";
import { type Env, readEnv } from "@config/env";
import { Argon2PasswordHasher } from "@infrastructure/crypto/argon2-password-hasher";
import { JwtAccessTokenService } from "@infrastructure/crypto/jwt-access-token.service";
import { OpaqueRefreshTokenSecrets } from "@infrastructure/crypto/opaque-refresh-token.secrets";
import { loadSigningKey, SIGNING_KEY, type SigningKey } from "@infrastructure/crypto/signing-key";
import { RefreshTokenRepositoryPrisma } from "@infrastructure/database/repositories/refresh-token.repository";
import { UserRepositoryPrisma } from "@infrastructure/database/repositories/user.repository";
import { AuthController, JwksController } from "@infrastructure/http/auth.controller";
import { JwtAuthGuard } from "@infrastructure/http/guards/jwt-auth.guard";
import { UsersController } from "@infrastructure/http/users.controller";
import { BootstrapAdminService } from "./bootstrap-admin.service";

const SESSION_DEPENDENCIES = Symbol("SESSION_DEPENDENCIES");
const clock = (): Date => new Date();

@Module({
  controllers: [AuthController, JwksController, UsersController],
  providers: [
    // Chave carregada e validada no boot: chave invalida impede a subida.
    {
      provide: SIGNING_KEY,
      useFactory: (config: ConfigService<Env, true>): Promise<SigningKey> =>
        loadSigningKey({
          pem: readEnv(config, "AUTH_PRIVATE_KEY_PEM"),
          file: readEnv(config, "AUTH_PRIVATE_KEY_FILE"),
        }),
      inject: [ConfigService],
    },
    { provide: USER_REPOSITORY, useClass: UserRepositoryPrisma },
    { provide: REFRESH_TOKEN_REPOSITORY, useClass: RefreshTokenRepositoryPrisma },
    { provide: PASSWORD_HASHER, useClass: Argon2PasswordHasher },
    { provide: REFRESH_TOKEN_SECRETS, useClass: OpaqueRefreshTokenSecrets },
    JwtAccessTokenService,
    { provide: ACCESS_TOKEN_ISSUER, useExisting: JwtAccessTokenService },
    JwtAuthGuard,
    {
      provide: SESSION_DEPENDENCIES,
      useFactory: (
        users: IUserRepository,
        refreshTokens: IRefreshTokenRepository,
        accessTokens: AccessTokenIssuer,
        secrets: RefreshTokenSecrets,
        config: ConfigService<Env, true>,
      ): SessionDependencies => ({
        users,
        refreshTokens,
        accessTokens,
        secrets,
        refreshTokenTtlSeconds: readEnv(config, "REFRESH_TOKEN_TTL_SECONDS"),
        clock,
      }),
      inject: [USER_REPOSITORY, REFRESH_TOKEN_REPOSITORY, ACCESS_TOKEN_ISSUER, REFRESH_TOKEN_SECRETS, ConfigService],
    },
    {
      provide: LoginUseCase,
      useFactory: (deps: SessionDependencies, hasher: PasswordHasher) => new LoginUseCase(deps, hasher),
      inject: [SESSION_DEPENDENCIES, PASSWORD_HASHER],
    },
    {
      provide: RefreshSessionUseCase,
      useFactory: (deps: SessionDependencies) => new RefreshSessionUseCase(deps),
      inject: [SESSION_DEPENDENCIES],
    },
    {
      provide: LogoutUseCase,
      useFactory: (refreshTokens: IRefreshTokenRepository, secrets: RefreshTokenSecrets) =>
        new LogoutUseCase(refreshTokens, secrets, clock),
      inject: [REFRESH_TOKEN_REPOSITORY, REFRESH_TOKEN_SECRETS],
    },
    {
      provide: CreateUserUseCase,
      useFactory: (users: IUserRepository, hasher: PasswordHasher) =>
        new CreateUserUseCase(users, hasher, clock),
      inject: [USER_REPOSITORY, PASSWORD_HASHER],
    },
    {
      provide: GetUserUseCase,
      useFactory: (users: IUserRepository) => new GetUserUseCase(users),
      inject: [USER_REPOSITORY],
    },
    {
      provide: BootstrapAdminUseCase,
      useFactory: (createUser: CreateUserUseCase, users: IUserRepository) =>
        new BootstrapAdminUseCase(createUser, users),
      inject: [CreateUserUseCase, USER_REPOSITORY],
    },
    BootstrapAdminService,
  ],
})
export class AuthModule {}
