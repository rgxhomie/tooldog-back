import { HttpException, HttpStatus, Injectable, UnauthorizedException } from '@nestjs/common';
import { registrationDto } from './dto/registration.dto';
import { UserService } from 'src/user/user.service';
import Role from 'src/user/roles.enum';
import { loginDto } from './dto/login.dto';
import * as bcrypt from 'bcryptjs';
import { TokenService } from 'src/token/token.service';
import { SessionService } from 'src/session/session.service';

@Injectable()
export class AuthService {
    constructor(
        private readonly userService: UserService,
        private readonly tokenService: TokenService,
        private readonly sessionService: SessionService
    ) {}

    async register (userData: registrationDto) {
        const existingEmail = await this.userService.getUserByEmail(userData.email);
        if (existingEmail) throw new HttpException('User with this email already exists', HttpStatus.BAD_REQUEST);

        const existingUsername = await this.userService.getUserByUsername(userData.username);
        if (existingUsername) throw new HttpException('User with this username already exists', HttpStatus.BAD_REQUEST);

        const createdUser = await this.userService.createUser({
            username: userData.username,
            email: userData.email,
            password: userData.password,
            role: Role.user
        });

        const pair = this.tokenService.generateTokenPair({
            userId: createdUser.id,
            role: createdUser.role,
            username: createdUser.username
        });
        
        this.sessionService.createSession(createdUser, pair.refresh, userData.clientId);

        return {
            pair,
            createdUser
        }
    }

    async login(loginData: loginDto) {
        const candidate = await this.userService.getUserByUsername(loginData.username);
        const isCorrectpassword = await bcrypt.compare(loginData.password, candidate?.pass_hash);

        if (!candidate || !isCorrectpassword) {
            throw new UnauthorizedException('Invalid usernamse or password');
        }

        const pair = this.tokenService.generateTokenPair({
            userId: candidate.id,
            role: candidate.role,
            username: candidate.username
        });
            
        this.sessionService.createSession(candidate, pair.refresh, loginData.clientId);
        
        return {
            pair,
            candidate
        }
    }
}
