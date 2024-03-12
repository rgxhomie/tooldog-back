import { IsString, IsEmail, IsNotEmpty, Length, IsAlphanumeric } from 'class-validator';

export class registrationDto {
  @IsString()
  @IsNotEmpty()
  @Length(5, 15)
  @IsAlphanumeric()
  readonly username: string;

  @IsEmail()
  @IsNotEmpty()
  readonly email: string;

  @IsString()
  @IsNotEmpty()
  @Length(8, 20)
  readonly password: string;
}
