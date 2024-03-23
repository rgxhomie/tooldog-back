import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/sequelize';
import { User } from './user.model';
import { createUserDto } from 'src/user/dto/createUser.dto';
import * as bcrypt from 'bcryptjs';
import * as _ from 'lodash';

@Injectable()
export class UserService {
    constructor (
        @InjectModel(User) private userRepository: typeof User
    ) {}

    async createUser(user: createUserDto) {
        const salt = bcrypt.genSaltSync(7);
        const pass_hash = bcrypt.hashSync(user.password, salt);

        const createdUser = await this.userRepository.create({
            email: user.email,
            username: user.username,
            pass_hash,
            role: user.role
        });

        return createdUser;
    }

    async getUserByUsername(username: string) {
        return await this.userRepository.findOne({where: {username}});
    }

    async getUserByEmail(email: string) {
        return await this.userRepository.findOne({where: {email}});
    }

    async getUserById(id: string) {
        return await this.userRepository.findOne({where: {id}});
    }
}
