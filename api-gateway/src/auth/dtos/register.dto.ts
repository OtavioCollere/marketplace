import { ApiProperty } from "@nestjs/swagger"
import { IsEmail, IsNotEmpty, IsOptional, IsString, MinLength } from "class-validator"

enum Role{
  USER = 'user',
  ADMIN = 'admin',
  SELLER = 'seller',
}

export class RegisterDto {
  @ApiProperty({
    description : 'Email do usuário',
    example : 'teste@teste.com'
  })
  @IsEmail()
  @IsNotEmpty()
  email : string

  @ApiProperty({
    description : 'Senha do usuário',
    example : '123456'
  })
  @IsString()
  @MinLength(6)
  password : string

  @ApiProperty({
    description : 'Primeiro nome do usuário',
    example : 'John'
  })
  @IsString()
  firstName : string

  @ApiProperty({
    description : 'Último nome do usuário',
    example : 'Doe'
  })
  @IsString()
  lastName : string

  @ApiProperty({
    description : 'Role do usuário',
    example : 'user',
    enum : Role,
    required : false
  })
  @IsOptional()
  @IsString()
  role? : Role
}