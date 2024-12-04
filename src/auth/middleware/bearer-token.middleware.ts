import {
  BadRequestException,
  Injectable,
  NestMiddleware,
  Next,
  UnauthorizedException,
} from '@nestjs/common';
import { NextFunction, Request, Response } from 'express';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { envVariablekeys } from 'src/common/const/env.const';

@Injectable()
export class BearerTokenMiddleware implements NestMiddleware {
  constructor(
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}
  async use(req: Request, res: Response, next: NextFunction) {
    const authHeader = req.headers['authorization'];

    // 토큰이 없는경우 , 인증할려는의도가 없는경우를 확인하기 위함

    if (!authHeader) {
      next();
      return;
    }
    const token = this.vaildateBearerToken(authHeader);

    // 리프레쉬 토큰이 이미 만료가 된상태를 처리해줘야된다.
    try {
      const decodedPayload = this.jwtService.decode(token);

      if (
        decodedPayload.type !== 'refresh' ||
        decodedPayload.type !== 'access'
      ) {
        throw new UnauthorizedException('잘못된 토큰입니다.');
      }

      const secretKey =
        decodedPayload.type === 'refresh'
          ? envVariablekeys.refreshTokenSecret
          : envVariablekeys.accessTokenSecret;

      const paylode = await this.jwtService.verifyAsync(token, {
        secret: this.configService.get<string>(secretKey),
      });

      req.user = paylode;
      Next();
    } catch (e) {
      //console.log(e);
      throw new UnauthorizedException(' 토큰이 만료되었습니다!', e);
    }
  }

  vaildateBearerToken(rawToken: string) {
    const basicSplit = rawToken.split(' ');

    //basicSplit 정상적으로왔다면 ['Basic','$token']
    if (basicSplit.length !== 2) {
      throw new BadRequestException(
        `토큰 포맷이 잘못되었습니다. 제공된 값: ${rawToken}`,
      );
    }

    const [bearer, token] = basicSplit;

    if (bearer.toLowerCase() !== 'bearer') {
      throw new BadRequestException(
        `토큰 포맷이 잘못되었습니다. Bearer가 없습니다: ${bearer}`,
      );
    }

    return token;
  }
}
