import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private config: ConfigService,
  ) {}
  async signIn(dto: AuthDto) {
    const user = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });

    if (!user) {
      throw new ForbiddenException('Credential Incorrect');
    }

    const pwMatch = await argon.verify(user?.hash, dto?.password);

    if (!pwMatch) {
      throw new ForbiddenException('Credential Incorrect');
    }

    return this?.signToken(user?.id, user?.email);
  }

  async signUp(dto: AuthDto) {
    const hash = await argon?.hash(dto?.password);

    try {
      const user = await this.prisma.user.create({
        data: { email: dto?.email, hash },
        select: { id: true, email: true, createdAt: true },
      });

      return this.signToken(user?.id, user?.email);
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new ForbiddenException('Credential Taken');
        }
      }
      throw error;
    }
  }

  async signToken(
    userId: number,
    email: string,
  ): Promise<{ access_token: string }> {
    const payload = {
      sub: userId,
      email,
    };
    const secret = await this.config.get('JWT_SECRET');
    return {
      access_token: this.jwt.sign(payload, { expiresIn: '15m', secret }),
    };
  }
}
