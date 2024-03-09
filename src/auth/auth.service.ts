import { Injectable } from '@nestjs/common';

@Injectable()
export class AuthService {
    async login (username: string, password: string) {}

    async logout () {}

    async register () {}

    async refresh () {}
}
