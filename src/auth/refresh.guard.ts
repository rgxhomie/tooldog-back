import 'dotenv/config';

import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';

const secret = process.env.JWT_REFRESH_SECRET;

@Injectable()
export class RefreshGuard implements CanActivate {
  constructor(
    private jwtService: JwtService
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {

    const request = context.switchToHttp().getRequest();

    const token = this.extractTokenFromHeader(request);
    if (!token) throw new UnauthorizedException();

    try {
        const payload = await this.jwtService.verifyAsync(token, {secret});
        
        request['sub'] = payload.sub;
        request['refresh_token'] = token;
    } catch {
      throw new UnauthorizedException();
    }

    return true;
  }

  private extractTokenFromHeader(request: Request): string | undefined {
    // @ts-ignore
    const token = request.headers['x-refresh-token'];
    return token;
  }
}
