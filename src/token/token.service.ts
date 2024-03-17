import { Injectable } from '@nestjs/common';

@Injectable()
export class TokenService {
    validateAccessToken() {}

    validateRefreshToken() {}

    generateTokenPair() {
        return {
            access: '',
            refresh: ''
        }
    }

    generateRefreshToken() {}

    generateAccessToken() {}
}
