import { PassportStrategy } from "@nestjs/passport";
import { Strategy, ExtractJwt } from "passport-jwt";
import { Injectable, UnauthorizedException } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { AuthService } from "../auth.service";

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private readonly authService : AuthService){
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: process.env.JWT_SECRET,
    })
  }

  async validate(payload : any) : Promise<any> {
    if (!payload) {
      throw new UnauthorizedException('Invalid token');
    }

    const user = await this.authService.validateJwtToken(payload.token);
    if(!user) {
      throw new UnauthorizedException('Invalid token');
    }

    return { 
      userId : payload.sub,
      email : user.payload.email,
      role : user.payload.role,
    };
  }
}