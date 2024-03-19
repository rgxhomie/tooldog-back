import { Module } from '@nestjs/common';
import { TestController } from './test.controller';
import { TestService } from './test.service';
import { TokenModule } from 'src/token/token.module';

@Module({
  controllers: [TestController],
  providers: [TestService],
  imports: [TokenModule]
})
export class TestModule {}
