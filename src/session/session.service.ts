import { Injectable } from '@nestjs/common';
import { Session } from './session.model';
import { InjectModel } from '@nestjs/sequelize';
import { User } from 'src/user/user.model';

@Injectable()
export class SessionService {
    constructor(
        @InjectModel(Session) private sessionRepository: typeof Session
    ) {}

    async createSession(user: User, token: string, clientid: string) {}

    async deleteSession(user: User, clientid: string) {}
}
