import { Injectable } from '@nestjs/common';
import * as jwt from 'jsonwebtoken';

@Injectable()
export class TokenService {
    validateAccessToken(token: string) {
        const secret = process.env.JWT_ACCESS_SECRET;

        try {
            jwt.verify(token, secret);

            return true;
        } catch (error) {
            return false;
        }
    }

    validateRefreshToken(token: string) {
        const secret = process.env.JWT_REFRESH_SECRET;

        try {
            jwt.verify(token, secret);

            return true;
        } catch (error) {
            return false;
        }
    }

    generateTokenPair(accessPayload: object = {}, refreshPayload: object = {}) {
        return {
            access: this.generateAccessToken(accessPayload),
            refresh: this.generateRefreshToken(refreshPayload)
        }
    }

    generateRefreshToken(payload: object = {}) {
        const secret = process.env.JWT_REFRESH_SECRET;
        const expiresIn = process.env.JWT_REFRESH_LIFESPAN;
        
        const token = jwt.sign(payload, secret, {expiresIn});

        return token;
    }

    generateAccessToken(payload: object = {}) {
        const secret = process.env.JWT_ACCESS_SECRET;
        const expiresIn = process.env.JWT_ACCESS_LIFESPAN;
        
        const token = jwt.sign(payload, secret, {expiresIn});

        return token;
    }
}
