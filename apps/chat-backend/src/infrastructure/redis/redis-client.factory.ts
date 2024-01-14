import { FactoryProvider } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { createClient } from 'redis';

export const redisClientFactory: FactoryProvider = {
  provide: 'RedisClient',
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  useFactory: (_configService: ConfigService) => {
    // const redisInstance = new Redis({
    //   port: configService.get<number>('REDIS_DB_PORT'),
    //   host: configService.get<string>('REDIS_DB_HOST')
    // });
    // const redisInstance = new Redis({
    //   port: 6380,
    //   host: 'redis-db',
    //   password: 'redis-stack'
    // });

    const redisInstance = createClient({
      socket: {
        port: 6380,
        host: 'redis-db'
      },
      password: 'redis-stack',
      pingInterval: 1000,
      legacyMode: true
    });

    redisInstance.on('error', (err) => {
      // throw new Error(`Redis connection failed: ${e}`);
      console.error(err);
      throw err;
    });

    return redisInstance;
  },
  inject: [ConfigService]
};
