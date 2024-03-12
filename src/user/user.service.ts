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
        const salt = bcrypt.genSaltSync(10);
        const pass_hash = bcrypt.hashSync(user.password, salt);

        const existingEmail = await this.userRepository.findOne({where: {email: user.email}});
        if (existingEmail) throw new HttpException('User with this email already exists', HttpStatus.BAD_REQUEST);

        const existingUserName = await this.userRepository.findOne({where: {username: user.username}});
        if (existingUserName) throw new HttpException('This username is already taken', HttpStatus.BAD_REQUEST);

        const createdUser = await this.userRepository.create({
            email: user.email,
            username: user.username,
            pass_hash,
            role: user.role
        });

        return createdUser.dataValues;
    }

    async getUserByUsername(username: string) {
        return await this.userRepository.findOne({where: {username}});
    }

}
