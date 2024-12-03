import {
  Controller,
  Get,
  Headers,
  Post,
  Request,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
// import { AuthGuard } from '@nestjs/passport';
import { LocalAuthGuard } from './strategy/local.strategy';
import { JwtAuthGuard } from './strategy/jwt.strategy';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  ///authorization : Basic $token
  registerUser(@Headers('authorization') token: string) {
    return this.authService.register(token);
  }

  @Post('login')
  loginUser(@Headers('authorization') token: string) {
    return this.authService.login(token);
  }

  /**
   *기본적인 모습은 local 로 표기한다.
   *  @UseGuards(AuthGuard('local'))안에 local 이라는 거대신에 표시를 다르게 하는방법은 아래와같아
   *
   * export class LocalStrategy extends PassportStrategy(Strategy, 'code') {
   * ...
   * }
   * 위 부분처럼 'code' 바꾸면
   * @UseGuards(AuthGuard('code')) 로 변경할수있다.
   *
   */
  @UseGuards(LocalAuthGuard)
  @Post('login/passport')
  async loginUserPassport(@Request() req) {
    return {
      refreshToken: await this.authService.issueToken(req.user, true), // accessToken을 재발급하기 위한 것
      accessToken: await this.authService.issueToken(req.user, false), // 사용자가 로그인된 상태임을 증명하고, 권한 및 인증 정보를 확인하기 위해 발급된 토큰
    };
  }

  @UseGuards(JwtAuthGuard)
  @Get('private')
  async private(@Request() req) {
    return req.user;
  }
}
