import Role from "../roles.enum";

export class createUserDto {
  readonly username: string;

  readonly email: string;

  readonly password: string;

  readonly role: Role;
}
