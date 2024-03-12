import { Module } from '@nestjs/common';
import { UserService } from './user.service';
import { SequelizeModule } from '@nestjs/sequelize';
import { User } from './user.model';

@Module({
    imports: [
        SequelizeModule.forFeature([User])
    ],
    exports: [
        UserService
    ],
    providers: [
        UserService
    ]
})
export class UserModule {}
