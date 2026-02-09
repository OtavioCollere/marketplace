import { ApiProperty } from "@nestjs/swagger"
import { IsEmail, IsNotEmpty, IsString, MinLength } from "class-validator"

export class LoginDto {
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
}