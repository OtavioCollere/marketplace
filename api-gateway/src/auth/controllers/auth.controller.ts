import { Body, Controller, HttpCode, HttpStatus, Post } from '@nestjs/common';
import { AuthService } from '../service/auth.service';
import { ApiBody, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { Throttle } from '@nestjs/throttler';
import { RegisterDto } from '../dtos/register.dto';
import { LoginDto } from '../dtos/login.dto';

@Controller('auth')
@ApiTags('Authentication')
export class AuthController {
  constructor(private readonly authService : AuthService){}

  @Post('login')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary : 'Login a user' })
  @ApiBody({ type: LoginDto })
  @ApiResponse({status: 200, description: 'Login successful'})
  @ApiResponse({status: 401, description: 'Invalid credentials'})
  @Throttle({ short : {limit : 5, ttl : 60000}}) // 5 requests per minute
  async login(@Body() loginDto : LoginDto) {
    return this.authService.login(loginDto)
  }

  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary : 'Register a new user' })
  @ApiBody({ type: RegisterDto })
  @ApiResponse({status: 201, description: 'Registration successfully'})
  @ApiResponse({status: 400, description: 'Invalid registration data'})
  @Throttle({ medium : {limit : 3, ttl : 60000}}) // 3 requests per minute
  async register(@Body() registerDto : RegisterDto ) {
    return this.authService.register(registerDto)
  }
}
