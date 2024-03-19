import { Body, Controller, Delete, Get, Headers, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { registrationDto } from 'src/auth/dto/registration.dto';
import { loginDto } from './dto/login.dto';

@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService) {}

    @Post('register')
    async register(
        @Body() body: registrationDto,
        @Headers('fingerprint') fp: string = 'unknown'
    ) {
        return await this.authService.register(body, fp);
    }

    @Post('login')
    async login(
        @Body() body: loginDto,
        @Headers('fingerprint') fp: string = 'unknown'
    ) {
        return await this.authService.login(body, fp);
    }

    @Get('refresh')
    async refresh() {}

    @Delete('logout')
    async logout(
        @Headers('fingerprint') fp: string = 'unknown'
    ) {
        return await this.authService.logout(fp);
    }

    @Delete('logoutAll')
    async logoutAll() {}
}
