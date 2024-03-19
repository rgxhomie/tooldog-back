import { Injectable } from '@nestjs/common';
import { Session } from './session.model';
import { InjectModel } from '@nestjs/sequelize';
import { User } from 'src/user/user.model';
import * as timestring from 'timestring';
import * as bcrypt from 'bcryptjs';

@Injectable()
export class SessionService {
    
    constructor(
        @InjectModel(Session) private sessionRepository: typeof Session
    ) {}

    async createSession(user: User, token: string, clientid: string) {
        const lifespanms = timestring(process.env.JWT_REFRESH_LIFESPAN, "ms");
        const expiresAt = new Date(Date.now() + lifespanms).toISOString();

        const salt = bcrypt.genSaltSync(7);
        const hash = bcrypt.hashSync(token, salt);

        await this.sessionRepository.create({
            userid: user.id,
            token: hash,
            clientid,
            expiresAt
        });
    }

    async findSession(user: User, clientId: string) {
        return await this.sessionRepository.findOne({where: {
            userid: user.id,
            clientid: clientId
        }});
    }

    async deleteSession(user: User, clientid: string) {
        const deletedCount = await this.sessionRepository.destroy({where: {
            userid: user.id,
            clientid
        }});

        return deletedCount < 1;
    }

    async deleteAllSessions(user: User) {
        const deletedCount = await this.sessionRepository.destroy({where: {
            userid: user.id
        }});

        return deletedCount < 1;
    }
}
