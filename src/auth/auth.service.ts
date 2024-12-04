import {
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Role, User } from 'src/user/entities/user.entity';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { envVariablekeys } from 'src/common/const/env.const';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    private readonly configService: ConfigService,
    private readonly jwtService: JwtService,
  ) {}
  parseBasicToken(rawToken: string) {
    //1)토큰 '' 기준으로 스플릿 하여 토큰 값만 추출 할것
    const basicSplit = rawToken.split(' ');

    //basicSplit 정상적으로왔다면 ['Basic','$token']
    if (basicSplit.length !== 2) {
      throw new NotFoundException('토큰 포멧이 잘못되었다1.');
    }

    const [basic, token] = basicSplit;

    if (basic.toLowerCase() !== 'basic') {
      throw new NotFoundException('토큰 포멧이 잘못되었다2.');
    }

    //2) 추출한 토큰을 base64 디코딩해서 이메일과 비밀번호로 나눈다.
    const decoded = Buffer.from(token, 'base64').toString('utf-8');

    /// 디코딩이 되고나면 여기까지는 email:password 가 되었다. 그러면 다시 아래에서 다시 나눠준다.
    const tokenSplit = decoded.split(':');

    if (tokenSplit.length !== 2) {
      throw new NotFoundException('토큰 포멧이 잘못되었다3.');
    }

    const [email, password] = tokenSplit;

    return {
      email,
      password,
    };
  }

  //accessToken 재발급 하는 엔드포인트

  async parseBearerToken(rawToken: string, isRefreshToken: boolean) {
    const basicSplit = rawToken.split(' ');

    //basicSplit 정상적으로왔다면 ['Basic','$token']
    if (basicSplit.length !== 2) {
      throw new NotFoundException('토큰 포멧이 잘못되었다4.');
    }

    const [bearer, token] = basicSplit;

    if (bearer.toLowerCase() !== 'bearer') {
      throw new NotFoundException('토큰 포멧이 잘못되었다5.');
    }

    // 리프레쉬 토큰이 이미 만료가 된상태를 처리해줘야된다.
    try {
      const paylode = await this.jwtService.verifyAsync(token, {
        secret: this.configService.get<string>(
          isRefreshToken
            ? envVariablekeys.refreshTokenSecret
            : envVariablekeys.accessTokenSecret,
        ),
      });
      if (isRefreshToken) {
        if (paylode.type !== 'refresh') {
          throw new NotFoundException('Refresh 토큰을 입력해주세요!');
        }
      } else {
        if (paylode.type !== 'access') {
          throw new NotFoundException('access 토큰을 입력해주세요!');
        }
      }

      return paylode;
    } catch (e) {
      throw new UnauthorizedException(' 토큰이 만료되었습니다.', e);
    }
  }

  //rawToken -> "Basic Stoken"
  async register(rawToken: string) {
    const { email, password } = this.parseBasicToken(rawToken);

    const user = await this.userRepository.findOne({
      where: {
        email,
      },
    });
    if (user) {
      throw new NotFoundException('이미 가입한 이메일입니다.');
    }

    const hash = await bcrypt.hash(
      password,
      this.configService.get<number>(envVariablekeys.hasRounds),
    );

    await this.userRepository.save({
      email,
      password: hash,
    });

    return this.userRepository.findOne({
      where: {
        email,
      },
    });
  }

  async authenticate(email: string, password: string) {
    const user = await this.userRepository.findOne({
      where: {
        email,
      },
    });
    if (!user) {
      throw new NotFoundException('잘못된 로그인 정보입니다.');
    }

    const passOk = await bcrypt.compare(password, user.password);
    if (!passOk) {
      throw new NotFoundException('잘못된 로그인 정보입니다.');
    }

    return user;
  }

  //ture 면 refreshToken  false 면 accessToken
  async issueToken(user: { id: number; role: Role }, isRefreshToken: boolean) {
    const refreshTokenSecret = this.configService.get<string>(
      envVariablekeys.refreshTokenSecret,
    );
    const accessTokenSecret = this.configService.get<string>(
      envVariablekeys.accessTokenSecret,
    );
    return this.jwtService.signAsync(
      {
        sub: user.id,
        role: user.role,
        type: isRefreshToken ? 'refresh' : 'access',
      },
      {
        secret: isRefreshToken ? refreshTokenSecret : accessTokenSecret,
        expiresIn: isRefreshToken ? '24h' : 300,
      },
    );
  }

  async login(rawToken: string) {
    const { email, password } = this.parseBasicToken(rawToken);

    // const user = await this.userRepository.findOne({
    //   where: {
    //     email,
    //   },
    // });
    // if (!user) {
    //   throw new NotFoundException('잘못된 로그인 정보입니다.');
    // }

    // const passOk = await bcrypt.compare(password, user.password);
    // if (!passOk) {
    //   throw new NotFoundException('잘못된 로그인 정보입니다.');
    // }

    const user = await this.authenticate(email, password);

    return {
      refreshToken: await this.issueToken(user, true),
      accessToken: await this.issueToken(user, false),
    };
  }
}
