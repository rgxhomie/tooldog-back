import Role from "src/user/roles.enum";

export class createTokenDto {
  readonly username: string;

  readonly role: Role;
}
