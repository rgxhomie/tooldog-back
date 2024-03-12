import { Column, DataType, Table, Model } from "sequelize-typescript";
import Role from "./user-roles.enum";

export interface IUserCreationAttributes {
    username: string,
    email: string,
    pass_hash: string,
    role: Role
}

@Table({
    tableName: 'users',
    schema: 'auth',
    paranoid: true,
})
export class User extends Model<User, IUserCreationAttributes> {
    @Column({
        type: DataType.UUID,
        primaryKey: true,
        allowNull: false,
        defaultValue: DataType.UUIDV4
    })
    id: string;

    @Column({
        type: DataType.STRING,
        unique: true,
        allowNull: false,
    })
    username: string;

    @Column({
        type: DataType.STRING,
        unique: true,
        allowNull: false,
    })
    email: string;

    @Column({
        type: DataType.STRING,
        allowNull: false,
    })
    pass_hash: string;

    @Column({
        type: DataType.STRING,
        allowNull: false,
    })
    role: Role;
}
