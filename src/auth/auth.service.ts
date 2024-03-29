import 'dotenv/config';

import { BadRequestException, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UsersService } from 'src/users/users.service';
import * as bcrypt from 'bcrypt';
import * as uuid from 'uuid';
import * as timestring from 'timestring';

const access_secret = process.env.JWT_ACCESS_SECRET;
const refresh_secret = process.env.JWT_REFRESH_SECRET;

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService
  ) {}

  async register(email: string, username: string, password: string) {
    const existingEmail = await this.usersService.user({email});
    if (existingEmail) throw new BadRequestException('User with this email already exists');

    const existingUsername = await this.usersService.user({username});
    if (existingUsername) throw new BadRequestException('User with this username already exists');

    const passHash = await bcrypt.hash(password, 7);

    const userId = uuid.v4();
    const tokenPair = await this.generateTokenPair(userId)

    await this.usersService.createUser({
      id: userId,
      email,
      username,
      password: passHash,
      refresh: tokenPair.refresh_token
    });

    return tokenPair;
  }

  async logIn(username: string, password: string) {
    const user = await this.usersService.user({username});
    if (!user) throw new UnauthorizedException();

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) throw new UnauthorizedException();
    
    const tokenPair = await this.generateTokenPair(user.id);

    await this.usersService.updateUser({
      where: {id: user.id},
      data: {refresh: tokenPair.refresh_token}
    });

    return tokenPair;
  }

  async logout(id: string): Promise<Record<string, boolean>>{
    const user = await this.usersService.user({id});

    if (!user) throw new BadRequestException();

    await this.usersService.updateUser({
      where: {id},
      data: {refresh: ''}
    });

    return { success: true };
  }

  async refresh(id: string, token: string): Promise<Record<string, string>> {
    const user = await this.usersService.user({id});

    if (!user || user.refresh !== token) throw new UnauthorizedException();

    return {
      access_token: await this.generateAccessToken(id)
    }
  }

  private async generateTokenPair(id: string): Promise<Record<string, string>> {
    const payload = { sub: id };

    const refresh_lifespan = timestring(process.env.JWT_REFRESH_LIFESPAN, 's');

    return {
      access_token: await this.generateAccessToken(id),
      refresh_token: await this.jwtService.signAsync(payload, {secret: refresh_secret, expiresIn: refresh_lifespan})
    };
  }

  private async generateAccessToken(id: string): Promise<string> {
    const payload = { sub: id };

    const access_lifespan = timestring(process.env.JWT_ACCESS_LIFESPAN, 's');

    return await this.jwtService.signAsync(payload, {secret: access_secret, expiresIn: access_lifespan});
  }
}
