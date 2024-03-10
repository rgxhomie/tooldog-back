import { HttpException, HttpStatus, Injectable, NestMiddleware } from '@nestjs/common';

@Injectable()
export class AuthMiddleware implements NestMiddleware {
  use(req: any, res: any, next: () => void) {
    const authHeader = req.headers['authorization'];
    if (!authHeader) {
      throw new HttpException('Unauthorized access', HttpStatus.UNAUTHORIZED);
    }
    // You can perform additional checks on the token if needed
    // For example, validate the token or decode its contents
    next();
  }
}
