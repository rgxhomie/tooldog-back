import { Injectable } from '@nestjs/common';
import * as jwt from 'jsonwebtoken';

@Injectable()
export class TokenService {
    validateAccessToken(token: string) {
        const secret = process.env.JWT_ACCESS_SECRET;

        try {
            const payload = jwt.verify(token, secret);

            return {
                isValid: true,
                payload
            };
        } catch (error) {
            return {
                isValid: false
            };
        }
    }

    validateRefreshToken(token: string) {
        const secret = process.env.JWT_REFRESH_SECRET;

        try {
            const payload = jwt.verify(token, secret);

            return {
                isValid: true,
                payload
            };
        } catch (error) {
            return {
                isValid: false
            };
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
