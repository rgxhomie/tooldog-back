import { Body, Controller, Get, Headers, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { registrationDto } from 'src/auth/dto/registration.dto';
import { loginDto } from './dto/login.dto';

@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService) {}

    @Post('register')
    async register(@Body() body: registrationDto) {
        return await this.authService.register(body);
    }

    @Post('login')
    async login(@Body() body: loginDto) {
        return await this.authService.login(body);
    }
}
