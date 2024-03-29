import { IsNotEmpty, IsString } from 'class-validator';

export class loginDto {
    @IsString()
    @IsNotEmpty()
    readonly username: string;
  
    @IsString()
    @IsNotEmpty()
    readonly password: string;
  }