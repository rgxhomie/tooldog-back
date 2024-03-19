import { CanActivate, ExecutionContext, HttpCode, HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { Observable } from 'rxjs';
import { TokenService } from 'src/token/token.service';

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(
    private readonly tokenServise: TokenService
  ){}

  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {
    const req = context.switchToHttp().getRequest();

    const header = req.headers['authorization'];
    if (!header) throw new HttpException('Unauthorized', HttpStatus.UNAUTHORIZED);

    const [scope, token] = header.split(' ');
    if (!scope || !token) throw new HttpException('Unauthorized', HttpStatus.UNAUTHORIZED);

    const validationResult = this.tokenServise.validateAccessToken(token);
    if (!validationResult.isValid || !validationResult.payload) throw new HttpException('Unauthorized', HttpStatus.UNAUTHORIZED);

    req.tokenPayload = validationResult.payload || {};

    return true;
  }
}
