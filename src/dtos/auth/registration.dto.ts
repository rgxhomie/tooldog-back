import { IsString, IsEmail } from 'class-validator';

export class registrationDto {
  @IsString()
  readonly username: string;

  @IsEmail()
  readonly email: string;

  @IsString()
  readonly password: string;
}
