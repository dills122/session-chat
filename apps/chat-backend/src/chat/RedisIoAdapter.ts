import { IoAdapter } from '@nestjs/platform-socket.io';
import { Server, ServerOptions } from 'socket.io';
import { createAdapter } from '@socket.io/redis-adapter';
import { createClient } from 'redis';
import * as util from '../shared/util';

import { INestApplication } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

const host = util.isLocal() ? 'localhost' : 'redis';

export class RedisIoAdapter extends IoAdapter {
  protected redisAdapter;

  constructor(app: INestApplication) {
    super(app);
    const configService = app.get(ConfigService);
    const port: string = configService.get('REDIS_PORT') || '';
    if (!port || port.length <= 0 || !host) {
      throw Error('Issue creating the Redis URL');
    }
    const pubClient = createClient({
      url: `redis://${host}:${port}`
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
