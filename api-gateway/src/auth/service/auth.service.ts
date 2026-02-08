import { HttpService } from '@nestjs/axios';
import { BadRequestException, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import type { UserSession } from '../interfaces/user-session.interface';
import { firstValueFrom } from 'rxjs';
import { serviceConfig } from 'src/config/gateway.config';

@Injectable()
export class AuthService {

  constructor(
    private readonly httpService : HttpService,
    private readonly jwtService : JwtService,
  ) {}

  async validateJwtToken(token : string) : Promise<any> {
    try{
      return this.jwtService.verify(token);
    } catch (error) {
      throw new UnauthorizedException('Invalid token');
    }
  }

  async validateSessionToken(sessionToken : string) : Promise<UserSession> {
    try{
      const  { data } = await firstValueFrom(
        this.httpService.get(
          `${serviceConfig.users.url}/sessions/validate/${sessionToken}`,
          {
            timeout : serviceConfig.users.timeout
          }
        )
      ) 
      
      return data;
    } catch (error) {
      throw new UnauthorizedException('Invalid session token');
    }
  }

  async login(loginDto : { email : string, password : string }) : Promise<any> {
    try{
      const { data } = await firstValueFrom(
        this.httpService.post(`${serviceConfig.users.url}/login`, loginDto, {
          timeout : serviceConfig.users.timeout
        })
      )

      return data;
    } catch (error) {
      throw new UnauthorizedException('Invalid login credentials');
    }
  }

  async register(registerDto : { email : string, password : string }) : Promise<any> {
    try{
      const { data } = await firstValueFrom(
        this.httpService.post(`${serviceConfig.users.url}/register`, registerDto, {
          timeout : serviceConfig.users.timeout
        })
      )

      return data;
    } catch (error) {
      throw new UnauthorizedException('Failed to register user');
    }

  }
}
