import { HttpException, HttpStatus, Injectable, UnauthorizedException } from '@nestjs/common';
import { registrationDto } from './dto/registration.dto';
import { UserService } from 'src/user/user.service';
import Role from 'src/user/user-roles.enum';
import { JwtService } from '@nestjs/jwt';
import { createUserDto } from 'src/user/dto/createUser.dto';
import { createTokenDto } from './dto/createToken.dto';
import { loginDto } from './dto/login.dto';
import * as bcrypt from 'bcryptjs';

@Injectable()
export class AuthService {
    constructor(
        private readonly userService: UserService,
        private readonly JWTService: JwtService
    ) {}

    async register (userData: registrationDto) {
        try {
            const createdUser = await this.userService.createUser({
                username: userData.username,
                email: userData.email,
                password: userData.password,
                role: Role.user
            });

            const token = this.generateToken({
                username: createdUser.username,
                role: createdUser.role
            });

            return {
                isSuccess: true,
                user: {
                    username: createdUser.username,
                    role: createdUser.role
                },
                token
            }
        } catch (error) {
            if (error instanceof HttpException) throw error;

            console.log('Error', {error});
            throw new HttpException('Internal Server Error', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async login(loginData: loginDto) {
        const candidate = await this.userService.getUserByUsername(loginData.username);
        if (!candidate) throw new UnauthorizedException('Invalid usernamse or password');

        const isCorrectpassword = await bcrypt.compare(loginData.password, candidate.pass_hash);
        if (isCorrectpassword) {
            const token = this.generateToken({
                username: candidate.username,
                role: candidate.role
            });
            return {
                isSuccess: true,
                user: {
                    username: candidate.username,
                    role: candidate.role
                },
                token
            }
        }

        throw new UnauthorizedException('Invalid usernamse or password');
    }

    private async generateToken(user: createTokenDto) {
        const payload = {username: user.username, role: user.role};
        return this.JWTService.sign(payload);
    }

    async validateToken(token: string) {
        try {
            return this.JWTService.verify<createTokenDto>(token)
        } catch (error) {
            throw new HttpException('Unauthorized access', HttpStatus.UNAUTHORIZED);
        }
    }
}
