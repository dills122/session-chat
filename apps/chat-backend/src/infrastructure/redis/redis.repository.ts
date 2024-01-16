import { Inject, Injectable, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { Redis } from 'ioredis';
import { RedisRepositoryInterface } from './redis.repository.interface';

@Injectable()
export class RedisRepository implements OnModuleInit, OnModuleDestroy, RedisRepositoryInterface {
  constructor(@Inject('RedisClient') private readonly redisClient: Redis) {}

  async onModuleInit() {
    const redisStatus = this.redisClient.status;
    if (redisStatus !== 'ready') {
      await this.redisClient.connect();
    }
  }

  onModuleDestroy(): void {
    this.redisClient.disconnect();
  }

  async get(key: string): Promise<string | null> {
    return this.redisClient.get(key);
  }

  async set(key: string, value: string): Promise<void> {
    await this.redisClient.set(key, value);
  }

  async delete(key: string): Promise<void> {
    await this.redisClient.del(key);
  }

  async setWithExpiry(key: string, value: string, expiry: number): Promise<void> {
    await this.redisClient.set(key, value, 'EX', expiry);
  }
}
