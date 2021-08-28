import { Injectable } from '@nestjs/common';
import jwt from 'jsonwebtoken';

@Injectable()
export class JwtTokenService {
  generateClientToken(username: string): Promise<string> {
    return new Promise((resolve, reject) => {
      return jwt.sign(
        username,
        'secret',
        {
          algorithm: 'ES512',
          expiresIn: '1d'
        },
        (err, token) => {
          if (err) {
            return reject(err);
          }
          return resolve(token);
        }
      );
    });
  }
}
