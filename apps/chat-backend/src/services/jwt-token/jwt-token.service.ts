import { Injectable } from '@nestjs/common';
import * as jwt from 'jsonwebtoken';
import * as fs from 'fs';
import { join } from 'path';
import { Logger } from '@nestjs/common';

export interface TokenInput {
  uid: string;
  room: string;
  token?: string;
}
@Injectable()
export class JwtTokenService {
  private privateKey: string;
  private logger: Logger = new Logger('JWTTokenService');

  generateClientToken(userData: TokenInput): Promise<string> {
    return new Promise((resolve, reject) => {
      if (!this.privateKey) {
        this.loadPrivateKey();
      }
      if (!this.privateKey) {
        return reject('Unable to load private key');
      }
      return jwt.sign(
        userData,
        this.privateKey,
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

  validateClientToken(tokenData: TokenInput): Promise<void> {
    return new Promise((resolve, reject) => {
      if (!tokenData.token) {
        return reject('missing token');
      }
      if (!this.privateKey) {
        this.loadPrivateKey();
      }
      if (!this.privateKey) {
        return reject('Unable to load private key');
      }
      return jwt.verify(
        tokenData.token,
        this.privateKey,
        {
          algorithms: ['ES512']
        },
        (err, decoded: TokenInput) => {
          if (err) {
            return reject(err);
          }
          if (decoded.room !== tokenData.room || decoded.uid !== decoded.uid) {
            return reject(Error('decoded data did not match'));
          }
          return resolve();
        }
      );
    });
  }

  private loadPrivateKey() {
    try {
      this.privateKey = fs
        .readFileSync(join(__dirname, '..', '..', '..', '..', 'keys', 'ecdsa-p521-private.pem'))
        .toString('utf-8'); //extra dir out due to dist on build
    } catch (err) {
      this.logger.error(err);
    }
  }
}
