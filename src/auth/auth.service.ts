import { BadRequestException, Injectable } from '@nestjs/common';
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

    async register (userData: registrationDto, clientId: string) {
        const existingEmail = await this.userService.getUserByEmail(userData.email);
        if (existingEmail) throw new BadRequestException('User with this email already exists');

        const existingUsername = await this.userService.getUserByUsername(userData.username);
        if (existingUsername) throw new BadRequestException('User with this username already exists');

        const createdUser = await this.userService.createUser({
            username: userData.username,
            email: userData.email,
            password: userData.password,
            role: Role.user
        });

        const pair = this.tokenService.generateTokenPair({
            id: createdUser.id,
            role: createdUser.role
        });
        
        this.sessionService.createSession(createdUser, pair.refresh, clientId);

        return {
            credentials: pair,
            user: {
                id: createdUser.id,
                username: createdUser.username,
                role: createdUser.role
            }
        }
    }

    async login(loginData: loginDto, clientId: string) {
        const candidate = await this.userService.getUserByUsername(loginData.username);
        const isCorrectpassword = await bcrypt.compare(loginData.password, candidate?.pass_hash || '');

        if (!candidate || !isCorrectpassword) {
            throw new BadRequestException('Invalid usernamse or password');
        }

        const pair = this.tokenService.generateTokenPair({
            id: candidate.id,
            role: candidate.role
        });
        
        const existingSession = await this.sessionService.findSession(candidate, clientId);
        if (existingSession) throw new BadRequestException('User logged in.');

        await this.sessionService.createSession(candidate, pair.refresh, clientId);
        
        return {
            credentials: pair,
            user: {
                id: candidate.id,
                username: candidate.username,
                role: candidate.role
            }
        }
    }
}
