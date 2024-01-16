import { Module } from '@nestjs/common';
import { redisClientFactory } from './redis-client.factory';
import { RedisRepository } from './redis.repository';
import { RedisService } from './redis.service';
import { ConfigModule } from '@nestjs/config';

@Module({
  imports: [ConfigModule],
  controllers: [],
  providers: [redisClientFactory, RedisRepository, RedisService],

  exports: [RedisService]
})
export class RedisModule {}
