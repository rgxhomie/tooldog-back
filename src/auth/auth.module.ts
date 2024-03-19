import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { UserModule } from 'src/user/user.module';
import { TokenModule } from 'src/token/token.module';
import { SessionModule } from 'src/session/session.module';

@Module({
    controllers: [
        AuthController
    ],
    providers: [
        AuthService
    ],
    imports: [
        UserModule,
        TokenModule,
        SessionModule
    ]
})
export class AuthModule {}
