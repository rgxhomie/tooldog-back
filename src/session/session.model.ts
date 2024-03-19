import { Column, DataType, Table, Model, ForeignKey } from "sequelize-typescript";
import { User } from "src/user/user.model";

export interface ISessionCreationAttributes {
    userid: string,
    clientid: string,
    expiresAt: string,
    token: string
}

@Table({
    tableName: 'sessions',
    schema: 'auth',
})
export class Session extends Model<Session, ISessionCreationAttributes> {

    @Column({
        type: DataType.STRING,
        allowNull: false,
    })
    token: string;

    @Column({
        type: DataType.STRING,
        allowNull: false,
    })
    @ForeignKey(() => User)
    userid: string;

    @Column({
        type: DataType.STRING,
        allowNull: false,
    })
    expiresAt: string;

    @Column({
        type: DataType.STRING,
        allowNull: false,
        primaryKey: true
    })
    clientid: string;
}
