import { Injectable } from '@nestjs/common';
import { RedisClient } from 'redis';
import { promisify } from 'util';

@Injectable()
export class RedisService {
  private client: RedisClient;

  constructor() {
    const REDIS_PORT = Number(process.env.REDIS_PORT || 6379);
    this.client = new RedisClient({ host: 'redis', port: REDIS_PORT });
  }

  get(key: string): Promise<string> {
    return promisify(this.client.get)(key);
  }

  set(key: string, value: string): void {
    promisify(this.client.set)(key, value);
  }

  delete(key: string): Promise<void> {
    return new Promise((resolve, reject) => {
      return this.client.del(key, (err) => {
        if (err) {
          return reject(err);
        }
        return resolve();
      });
    });
  }
}
