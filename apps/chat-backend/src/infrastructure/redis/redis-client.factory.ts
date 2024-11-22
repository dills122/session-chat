import { FactoryProvider } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { createClient } from 'redis';

export const redisClientFactory: FactoryProvider = {
  provide: 'RedisClient',
  useFactory: (configService: ConfigService) => {
    const redisInstance = createClient({
      socket: {
        port: configService.get<number>('REDIS_DB_PORT'),
        host: configService.get<string>('REDIS_DB_HOST')
      },
      password: configService.get<string>('DB_PASS_STR')
    });

    redisInstance.on('error', (err) => {
      // throw new Error(`Redis connection failed: ${e}`);
      console.warn('Error REDIS-DB');
      console.error(err);
      throw err;
    });

    return redisInstance;
  },
  inject: [ConfigService]
};
