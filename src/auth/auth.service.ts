import { Injectable } from '@nestjs/common';

@Injectable()
export class AuthService {
    async login (username: string, password: string) {
        return 'You are in login';
    }

    async logout (authHeader: string) {
        return 'You are in logout';
    }

    async register (username: string, email: string, password: string) {
        return 'You are in register';
    }

    async refresh (refreshToken) {
        return 'You are in refresh';
    }
}
