import { Injectable } from '@nestjs/common';
import { Session } from './session.model';
import { InjectModel } from '@nestjs/sequelize';

@Injectable()
export class SessionService {
    constructor(
        @InjectModel(Session) private userRepository: typeof Session
    ) {}

    async createSession() {}

    async deleteSession() {}
}
