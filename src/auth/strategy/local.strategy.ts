import { Injectable } from '@nestjs/common';
import { AuthGuard, PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-local';
import { AuthService } from '../auth.service';

/**
 * 컨트롤러에서 사용한 AuthGuard -> @UseGuards(AuthGuard('local'))
 * 직업 만들기( 커스텀 )
 *
 */
export class LocalAuthGuard extends AuthGuard('code') {}

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy, 'code') {
  constructor(private readonly AuthService: AuthService) {
    /**
     * { usernameField: 'email' } 으로 표기하면
     *  body 값에 username을  email 로 변경할수있다.
     */
    super({ usernameField: 'email' });
  }
  //실제로 존재하는 사용자인지 검증하는 것
  /**
   * localstrategy
   *
   * validate: username, password
   *
   * return -> Request();
   */
  async validate(email: string, password: string) {
    const user = await this.AuthService.authenticate(email, password);

    return user;
  }
}
