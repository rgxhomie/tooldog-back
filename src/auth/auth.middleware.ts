import { HttpException, HttpStatus, Injectable, NestMiddleware } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthMiddleware implements NestMiddleware {
  constructor(
    private readonly jwtService: JwtService
  ) {}

  use(req: any, res: any, next: () => void) {
    const authHeader = req.headers['authorization'];
    if (!authHeader) {
      throw new HttpException('Unauthorized access', HttpStatus.UNAUTHORIZED);
    }
    
    try {
      this.jwtService.verify(authHeader);
    } catch (error) {
      throw new HttpException('Unauthorized access', HttpStatus.UNAUTHORIZED);
    }

    next();
  }
}
