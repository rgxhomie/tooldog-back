import Role from "src/user/user-roles.enum";

export class createTokenDto {
  readonly username: string;

  readonly role: Role;
}
