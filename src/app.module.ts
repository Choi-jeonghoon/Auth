import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { AuthModule } from './auth/auth.module';
import { UserModule } from './user/user.module';
import * as Joi from 'joi';
import { User } from './user/entities/user.entity';

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
        HASH_ROUNDS: Joi.number().required(),
      }),
    }),
    // TypeOrmModule.forRootAsync를 사용하는 이유는 ConfigService와 같은 비동기 서비스로부터 설정을 동적으로 가져오기 위함이다.
    TypeOrmModule.forRootAsync({
      // useFactory는 ConfigService를 통해 동적으로 DB 설정을 가져오기 위한 함수이다.
      useFactory: (configService: ConfigService) => ({
        type: configService.get<string>('DB_TYPE') as 'postgres', // 데이터베이스 타입을 동적으로 가져옴
        host: configService.get<string>('DB_HOST'), // 호스트명을 동적으로 가져옴
        port: configService.get<number>('DB_PORT'), // 포트 번호를 동적으로 가져옴
        username: configService.get<string>('DB_USERNAME'), // 사용자 이름을 동적으로 가져옴
        password: configService.get<string>('DB_PASSWORD'), // 비밀번호를 동적으로 가져옴
        database: configService.get<string>('DB_DATABASE'), // 사용할 데이터베이스 이름을 동적으로 가져옴
        entities: [User], // 사용할 엔티티 리스트
        synchronize: true, // 개발 환경에서는 true로 설정하여 엔티티와 DB 스키마를 자동으로 동기화
      }),
      inject: [ConfigService], // ConfigService를 주입받아 설정을 가져옴
    }),
    AuthModule,
    UserModule,
  ],
})
export class AppModule {}

/*@MEMO
비동기 설정: ConfigModule을 통해 환경변수나 설정값을 비동기적으로 불러온 후, TypeOrmModule이 해당 설정값을 기반으로 데이터베이스에 연결할 수 있도록 비동기로 처리.
IOC 컨테이너: 의존성 주입 및 설정이 완료된 후에 TypeOrmModule이 올바르게 초기화되도록 순서를 보장.
*/
