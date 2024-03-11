import { Column, DataType, Table, Model } from "sequelize-typescript";

export interface IUserCreationAttributes {
    id: string,
    username: string,
    email: string,
    pass_hash: string
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
        unique: true,
        allowNull: false,
    })
    pass_hash: string;
}
