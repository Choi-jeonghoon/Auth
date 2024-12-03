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
   * @MEMO
   * 프론트엔드에서 로그인을 하면 서버에서 `accessToken`과 `refreshToken`을 발급받는다.
   *
   * - **accessToken**: 유효 기간이 짧고, 사용자가 서버의 보호된 리소스에 접근할 때 사용한다.
   *   예) API 호출 시 Authorization 헤더에 `Bearer <accessToken>`을 담아 요청
   *   ```
   *   Authorization: Bearer eyJhbGciOiJIUz...
   *   ```
   *
   * - **refreshToken**: 유효 기간이 길고, accessToken이 만료되었을 때 새로운 accessToken을 발급받는 데 사용한다.
   *   refreshToken은 클라이언트가 안전한 스토리지(예: HttpOnly 쿠키)에서 관리해야 한다.
   *
   * - 로그인 후 사용자는 두 개의 토큰을 모두 들고 있으며, 다음과 같은 흐름으로 동작한다:
   *   1. **accessToken 사용**:
   *      - 사용자는 보호된 리소스를 요청할 때 `accessToken`을 전송한다.
   *      - `accessToken`의 유효성이 확인되면 요청이 정상적으로 처리된다.
   *   2. **accessToken 만료 시**:
   *      - `refreshToken`을 사용하여 서버에서 새로운 `accessToken`을 요청한다.
   *      - 새로운 `accessToken`이 발급되면 다시 리소스를 요청할 수 있다.
   */

  //accessToken 재발급 하는 엔드포인트 ( refreshToken 이 있어야 된다.)
  @Post('Token/access')
  async rotateAccessToken(@Headers('authorization') token: string) {
    const payload = await this.authService.parseBearerToken(token, true);
    return { accessToken: await this.authService.issueToken(payload, false) };
  }

  //아래는 passport 관련 엔드포인트

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
