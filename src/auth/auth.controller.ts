import { Body, Controller, Delete, Get, Headers, Post, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { registrationDto } from 'src/auth/dto/registration.dto';
import { loginDto } from './dto/login.dto';
import { AuthGuard } from './auth.guard';

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

    @UseGuards(AuthGuard)
    @Delete('logout')
    async logout(
        @Headers('fingerprint') fp: string = 'unknown',
        @Headers('authorization') token
    ) {
        return await this.authService.logout(fp, token);
    }

    @UseGuards(AuthGuard)
    @Delete('logoutAll')
    async logoutAll(
        @Headers('authorization') token
    ) {
        return await this.authService.logoutAll(token);
    }
}
