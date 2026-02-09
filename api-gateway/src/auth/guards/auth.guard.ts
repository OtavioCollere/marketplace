import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { Observable } from 'rxjs';
import { AuthGuard } from '@nestjs/passport';
import { Reflector } from '@nestjs/core';

interface JwtUser {
  userId : string;
  email : string;
  role : string;
}

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {

  
  constructor(
    private readonly reflector : Reflector // Pegar os metadados da requisicao
  ) {
    super();
  }

  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {
    const isPublic = this.reflector.getAllAndOverride<boolean>('isPublic', [
      context.getHandler(),
      context.getClass()
    ]); 

    if (isPublic) return true;

    return super.canActivate(context);
  }

  handleRequest<TUser = JwtUser>(
    err: Error, 
    user: JwtUser | false, 
    _info: unknown,
    context : ExecutionContext,
    status? : unknown
  ) : TUser {
    if (err || !user) { 
      throw err || new UnauthorizedException();
    }

    return user as TUser;
  }
}
