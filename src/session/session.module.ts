import { Module } from '@nestjs/common';
import { SessionService } from './session.service';
import { Session } from './session.model';
import { SequelizeModule } from '@nestjs/sequelize';

@Module({
  imports: [SequelizeModule.forFeature([Session])],
  providers: [SessionService],
  exports: [SessionService]
})
export class SessionModule {}
