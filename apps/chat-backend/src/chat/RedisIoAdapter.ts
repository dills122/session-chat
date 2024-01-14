import { IoAdapter } from '@nestjs/platform-socket.io';
import { createAdapter } from '@socket.io/redis-adapter';
import { createClient } from 'redis';
import { Server, ServerOptions } from 'socket.io';

import { INestApplicationContext } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

export class RedisIoAdapter extends IoAdapter {
  protected redisAdapter;

  constructor(private app: INestApplicationContext) {
    super(app);
    const configService = this.app.get(ConfigService);
    const port = configService.get<number>('REDIS_IO_PORT');
    const host = configService.get<string>('REDIS_IO_HOST');
    if (!port || !host) {
      throw Error('Issue creating the Redis URL');
    }
    const pubClient = createClient({
      socket: {
        host: 'redis',
        port: 6379
      },
      pingInterval: 1000,
      legacyMode: true
    });

    pubClient.on('error', function (error) {
      console.error(error);
    });

    const subClient = pubClient.duplicate();

    pubClient.connect(); // <------
    subClient.connect(); // <------

    this.redisAdapter = createAdapter(pubClient, subClient);
  }

  createIOServer(port: number, options?: ServerOptions) {
    const server = super.createIOServer(port, options) as Server;

    server.adapter(this.redisAdapter);

    return server;
  }
}
