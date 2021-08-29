import { Injectable } from '@nestjs/common';
import * as jwt from 'jsonwebtoken';
import * as fs from 'fs';
import { join } from 'path';
@Injectable()
export class JwtTokenService {
  generateClientToken(username: string): Promise<string> {
    return new Promise((resolve, reject) => {
      const privateKey = fs.readFileSync(
        join(__dirname, '..', '..', '..', '..', 'keys', 'ecdsa-p521-private.pem')
      ); //extra dir out due to dist on build
      return jwt.sign(
        {
          username: username
        },
        privateKey.toString('utf-8'),
        {
          algorithm: 'ES512'
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
