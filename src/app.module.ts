import {
  MiddlewareConsumer,
  Module,
  NestModule,
  RequestMethod,
} from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { AuthModule } from './auth/auth.module';
import { UserModule } from './user/user.module';
import * as Joi from 'joi';
import { User } from './user/entities/user.entity';
import { envVariablekeys } from './common/const/env.const';
import { BearerTokenMiddleware } from './auth/middleware/bearer-token.middleware';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true, // ConfigModule을 전역 모듈로 설정하여 어느 모듈에서도 설정값을 접근할 수 있도록 함
      validationSchema: Joi.object({
        ENV: Joi.string().valid('dev', 'prod').required(), // ENV 값은 dev 또는 prod 중 하나여야 하며 필수값이다.
        DB_TYPE: Joi.string().valid('postgres').required(), // DB_TYPE은 'postgres'여야 하며 필수값이다.
        DB_HOST: Joi.string().required(), // DB 호스트는 필수값이다.
        DB_PORT: Joi.number().required(), // DB 포트는 숫자여야 하며 필수값이다.
        DB_USERNAME: Joi.string().required(), // DB 사용자 이름은 필수값이다.
        DB_PASSWORD: Joi.string().required(), // DB 비밀번호는 필수값이다.
        DB_DATABASE: Joi.string().required(),
        HASH_ROUNDS: Joi.number().required(),
        ACCESS_TOKEN_SECRET: Joi.string().required(),
        REFRESH_TOKEN_SECRET: Joi.string().required(),
      }),
    }),
    // TypeOrmModule.forRootAsync를 사용하는 이유는 ConfigService와 같은 비동기 서비스로부터 설정을 동적으로 가져오기 위함이다.
    TypeOrmModule.forRootAsync({
      // useFactory는 ConfigService를 통해 동적으로 DB 설정을 가져오기 위한 함수이다.
      useFactory: (configService: ConfigService) => ({
        type: configService.get<string>(envVariablekeys.dbType) as 'postgres', // 데이터베이스 타입을 동적으로 가져옴
        host: configService.get<string>(envVariablekeys.dbHost), // 호스트명을 동적으로 가져옴
        port: configService.get<number>(envVariablekeys.dbPort), // 포트 번호를 동적으로 가져옴
        username: configService.get<string>(envVariablekeys.dbUsername), // 사용자 이름을 동적으로 가져옴
        password: configService.get<string>(envVariablekeys.dbPassword), // 비밀번호를 동적으로 가져옴
        database: configService.get<string>(envVariablekeys.dbDatabase), // 사용할 데이터베이스 이름을 동적으로 가져옴
        entities: [User], // 사용할 엔티티 리스트
        synchronize: true, // 개발 환경에서는 true로 설정하여 엔티티와 DB 스키마를 자동으로 동기화
      }),
      inject: [ConfigService], // ConfigService를 주입받아 설정을 가져옴
    }),
    AuthModule,
    UserModule,
  ],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer
      .apply(BearerTokenMiddleware)
      .exclude(
        /**
         * 아래 두 엔드포인트에서는 bearer 토큰이 아닌 basic을 사용한다.
         * 그러므로 해당 엔드포인트는 제외를 해야된다.
         */
        { path: 'auth/login', method: RequestMethod.POST },
        { path: 'auth/register', method: RequestMethod.POST },
      )
      .forRoutes('*'); //모든곳에서 사용하게 하기위함
  }
}

/*@MEMO
비동기 설정: ConfigModule을 통해 환경변수나 설정값을 비동기적으로 불러온 후, TypeOrmModule이 해당 설정값을 기반으로 데이터베이스에 연결할 수 있도록 비동기로 처리.
IOC 컨테이너: 의존성 주입 및 설정이 완료된 후에 TypeOrmModule이 올바르게 초기화되도록 순서를 보장.
*/
