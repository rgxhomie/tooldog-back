import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/sequelize';
import { User } from './user.model';
import { createUserDto } from 'src/dtos/user/createUser.dto';

@Injectable()
export class UserService {
    constructor (
        @InjectModel(User) private userRepository: typeof User
    ) {}

    async createUser(userData: createUserDto) {
        
    }

    async getUser() {}

    async deleteUser() {}

    async getAllUsers() {}
}
