import {
  ArrayMaxSize,
  ArrayMinSize,
  IsArray,
  IsEmail,
  IsIn,
  IsString,
  MaxLength,
  MinLength,
} from "class-validator";
import { ROLES } from "@domain/entities/user.entity";
import { EMAIL_MAX_LENGTH } from "@domain/value-objects/email.value-object";
import { PASSWORD_MAX_LENGTH, PASSWORD_MIN_LENGTH } from "@domain/value-objects/password-policy";

export class LoginDto {
  @IsEmail()
  @MaxLength(EMAIL_MAX_LENGTH)
  readonly email!: string;

  // Sem MinLength no login: a politica vale no cadastro; aqui so o teto.
  @IsString()
  @MaxLength(PASSWORD_MAX_LENGTH)
  readonly password!: string;
}

export class RefreshTokenDto {
  @IsString()
  @MinLength(1)
  @MaxLength(512)
  readonly refreshToken!: string;
}

export class CreateUserDto {
  @IsEmail()
  @MaxLength(EMAIL_MAX_LENGTH)
  readonly email!: string;

  @IsString()
  @MinLength(PASSWORD_MIN_LENGTH)
  @MaxLength(PASSWORD_MAX_LENGTH)
  readonly password!: string;

  @IsArray()
  @ArrayMinSize(1)
  @ArrayMaxSize(ROLES.length)
  @IsIn(ROLES, { each: true })
  readonly roles!: string[];
}

export class TokenPairResponseDto {
  readonly tokenType!: "Bearer";
  readonly accessToken!: string;
  readonly expiresIn!: number;
  readonly refreshToken!: string;
  readonly refreshExpiresIn!: number;
}

export class UserResponseDto {
  readonly id!: string;
  readonly email!: string;
  readonly roles!: string[];
  readonly active!: boolean;
  readonly createdAt!: string;
}
