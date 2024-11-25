import { Inject, Injectable, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { RedisRepositoryInterface } from './redis.repository.interface';
import { RedisClientType } from 'redis';

@Injectable()
export class RedisRepository implements OnModuleInit, OnModuleDestroy, RedisRepositoryInterface {
  constructor(@Inject('RedisClient') private readonly redisClient: RedisClientType) {}

  async onModuleInit() {
    const isReady = this.redisClient.isReady;
    if (!isReady) {
      await this.redisClient.connect();
    }
  }

  onModuleDestroy(): void {
    this.redisClient.disconnect();
  }

  async get(key: string): Promise<string | null> {
    return await this.redisClient.get(key);
  }

  async set(key: string, value: string): Promise<void> {
    await this.redisClient.set(key, value);
  }

  async delete(key: string): Promise<void> {
    await this.redisClient.del(key);
  }

  async setWithExpiry(key: string, value: string, expiry: number): Promise<void> {
    await this.redisClient.set(key, value, {
      EX: expiry
    });
  }
}
