import { Body, Controller, Get, Post, UseGuards } from "@nestjs/common";
import { SkipThrottle } from "@nestjs/throttler";
import { CreateUserUseCase, GetUserUseCase } from "@application/use-cases/user.use-cases";
import type { VerifiedPrincipal } from "@infrastructure/crypto/jwt-access-token.service";
import { CreateUserDto, type UserResponseDto } from "./dto/auth.dto";
import { CurrentPrincipal, JwtAuthGuard, RequireRoles } from "./guards/jwt-auth.guard";
import { toUserResponse } from "./mappers/auth-response.mapper";

// O ms-auth valida o proprio token (nao confia so no gateway): cadastro de
// usuario e a operacao mais sensivel da plataforma.
@Controller("users")
@UseGuards(JwtAuthGuard)
@SkipThrottle({ login: true })
export class UsersController {
  constructor(
    private readonly createUser: CreateUserUseCase,
    private readonly getUser: GetUserUseCase,
  ) {}

  @Post()
  @RequireRoles("admin")
  async create(@Body() dto: CreateUserDto): Promise<UserResponseDto> {
    return toUserResponse(await this.createUser.execute(dto));
  }

  @Get("me")
  async me(@CurrentPrincipal() principal: VerifiedPrincipal): Promise<UserResponseDto> {
    return toUserResponse(await this.getUser.execute(principal.userId));
  }
}
