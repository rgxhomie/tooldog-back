import { Body, Controller, Get, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { loginDto } from 'src/dtos/auth/login.dto';

@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService) {}

    @Post()
    login(@Body() body: loginDto) {
        return this.authService.login(body.password, body.username);
    }

    @Post()
    logout() {
        return ;
    }

    @Post()
    register() {
        return ;
    }

    @Get()
    refresh() {
        return ;
    }
}
