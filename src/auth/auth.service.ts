import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from 'src/user/entities/user.entity';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';

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

    const [, token] = basicSplit;

    //2) 추출한 토큰을 base64 디코딩해서 이메일과 비밀번호로 나눈다.
    const decoded = Buffer.from(token, 'base64').toString('utf-8');

    /// 디코딩이 되고나면 여기까지는 email:password 가 되었다. 그러면 다시 아래에서 다시 나눠준다.
    const tokenSplit = decoded.split(':');

    if (tokenSplit.length !== 2) {
      throw new NotFoundException('토큰 포멧이 잘못되었다2.');
    }

    const [email, password] = tokenSplit;

    return {
      email,
      password,
    };
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
      this.configService.get<number>('HASH_ROUNDS'),
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

    const refreshTokenSecret = this.configService.get<string>(
      'REFRESH_TOKEN_SECRET',
    );
    const accessTokenSecret = this.configService.get<string>(
      'ACCESS_TOKEN_SECRET',
    );

    return {
      refreshToken: await this.jwtService.signAsync(
        {
          sub: user.id,
          role: user.role,
          type: 'refresh',
        },
        { secret: refreshTokenSecret, expiresIn: '24h' },
      ),
      accessToken: await this.jwtService.signAsync(
        {
          sub: user.id,
          role: user.role,
          type: 'access',
        },
        { secret: accessTokenSecret, expiresIn: 300 },
      ),
    };
  }
}
