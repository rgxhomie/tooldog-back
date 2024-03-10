import { MiddlewareConsumer, Module, ValidationPipe } from '@nestjs/common';
import { APP_PIPE } from '@nestjs/core';
import { AuthMiddleware } from './auth/auth.middleware';
import { SequelizeModule } from '@nestjs/sequelize';
import { AuthModule } from './auth/auth.module';
import { ConfigModule } from '@nestjs/config';

@Module({
  imports: [
    ConfigModule.forRoot({
      envFilePath: '.env'
    }),
    SequelizeModule.forRoot({
      dialect: 'postgres',
      host: 'localhost',
      port: 5432,
      username: '',
      password: '',
      database: '',
      models: [],
      autoLoadModels: true
    }),
    AuthModule
  ],
  controllers: [
  ],
  providers: [
    {
      provide: APP_PIPE,
      useClass: ValidationPipe,
    }
  ],
})
export class AppModule {
  configure(
    consumer: MiddlewareConsumer
  ) {
    consumer.apply(AuthMiddleware).forRoutes(
      '*'
    );
  }
}
