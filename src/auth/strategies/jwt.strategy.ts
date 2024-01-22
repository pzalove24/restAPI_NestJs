import { Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { PassportStrategy } from '@nestjs/passport';
import { Model } from 'mongoose';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { User } from '../schemas/user.schema';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    @InjectModel(User.name)
    private userModel: Model<User>,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: process.env.JWT_SECRET,
    });
  }

  // token will come first, then got validate and extract data from super, which we can get id in return
  async validate(payload) {
    const { id } = payload;

    console.log('payload', payload)

    const user = await this.userModel.findById(id);

    if (!user) {
      throw new UnauthorizedException('Login First to access this endpoint.');
    }

    return user;
  }
}
