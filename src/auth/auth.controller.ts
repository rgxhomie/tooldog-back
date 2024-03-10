import { Body, Controller, Get, Headers, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { loginDto } from 'src/dtos/auth/login.dto';
import { registrationDto } from 'src/dtos/auth/registration.dto';

@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService) {}

    @Post('login')
    async login(@Body() body: loginDto) {
        return await this.authService.login(body.password, body.username);
    }

    @Post('logout')
    async logout(@Headers('Authorization') authHeader: string) {
        return await this.authService.logout(authHeader);
    }

    @Post('register')
    async register(@Body() body: registrationDto) {
        return await this.authService.register(body.username, body.email, body.password);
    }

    @Get('refresh')
    async refresh(@Headers('Authorization') authHeader: string) {
        return await this.authService.refresh(authHeader);
    }
}
