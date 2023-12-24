import { Injectable } from '@nestjs/common';
import * as jwt from 'jsonwebtoken';
import * as fs from 'fs';
import { join } from 'path';
import { Logger } from '@nestjs/common';

export interface TokenValidationInput extends UserDataInput {
  token: string;
}

export interface UserDataInput {
  uid: string;
  room: string;
}

@Injectable()
export class JwtTokenService {
  private privateKey: string;
  private logger: Logger = new Logger('JWTTokenService');

  generateClientToken(userData: UserDataInput): Promise<string> {
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
          if (err || !token) {
            return reject(err);
          }
          return resolve(token);
        }
      );
    });
  }

  validateClientToken(tokenData: TokenValidationInput): Promise<void> {
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
      const decoded = jwt.verify(tokenData.token, this.privateKey, {
        algorithms: ['ES512']
      });

      if (decoded && typeof decoded !== 'string') {
        const matchingRoom = decoded.room === tokenData.room;
        const matchingUid = decoded.uid === decoded.uid;
        if (!matchingRoom || !matchingUid) {
          return reject(Error('decoded data did not match'));
        }
      }
      return resolve();
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
