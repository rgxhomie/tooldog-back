import { Body, Controller, Get, HttpCode, HttpStatus, Post, UseGuards, Request, Delete } from '@nestjs/common';
import { AuthService } from './auth.service';
import { Public } from 'src/auth/public.decorator';
import { loginDto } from './types/login.dto';
import { registrationDto } from './types/registration.dto';
import { RefreshGuard } from './refresh.guard';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Public()
  @Post('register')
  async register(@Body() registrationDto: registrationDto) {
    return await this.authService.register(
      registrationDto.email, 
      registrationDto.username, 
      registrationDto.password
    );
  }

  @Public()
  @Post('login')
  async logIn(@Body() logInDto: loginDto) {
    return await this.authService.logIn(logInDto.username, logInDto.password);
  }

  @Public()
  @UseGuards(RefreshGuard)
  @Delete('logout')
  async logout(@Request() request) {
    const { sub } = request;

    return this.authService.logout(sub);
  }

  @Public()
  @UseGuards(RefreshGuard)
  @Get('refresh')
  async refresh(@Request() request) {
    const { sub, refresh_token } = request;

    return this.authService.refresh(sub, refresh_token);
  }
}
