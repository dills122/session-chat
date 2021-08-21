import { Injectable } from '@nestjs/common';
import { createClient, RedisClient } from 'redis';
import { Server } from 'socket.io';
import { MessageFormat } from 'src/shared/types';
import async from 'async';

@Injectable()
export class RedisCacheService {
  private serviceId: string;
  private subscriberClient: RedisClient;
  private publisherClient: RedisClient;
  private redisClient: RedisClient;
  constructor() {
    this.serviceId = 'SOCKET_CHANNEL_' + Math.random().toString(26).slice(2);
    this.redisClient = this.createClient();
    this.redisClient.setex(this.serviceId, 3, Date.now().toString());
  }

  registerSubscriber(wss: Server): void {
    this.subscriberClient = this.createClient();
    this.subscriberClient.subscribe(this.serviceId);

    this.subscriberClient.on('message', (channel: string, payload: string) => {
      const message = JSON.parse(payload) as MessageFormat;
      wss.to(message.room).emit('chatToClient', message);
    });
  }
  registerPublisher(): void {
    this.publisherClient = this.createClient();
  }

  publishMessageToStore(message: MessageFormat): Promise<void> {
    return new Promise((resolve, reject) => {
      async.waterfall(
        [
          (next) => this.redisClient.keys('SOCKET_CHANNEL_*', next),
          (ids: string[], next) => {
            const filteredIds = ids.filter((socketChannelIds) => socketChannelIds !== this.serviceId);
            return async.each(
              filteredIds,
              (id, cb) => {
                return this.publisherClient.publish(id, JSON.stringify(message), cb);
              },
              next
            );
          }
        ],
        (err) => {
          if (err) {
            return reject(err);
          }
          return resolve();
        }
      );
    });
  }

  private createClient(): RedisClient {
    return createClient({
      host: 'localhost',
      port: 6379
    });
  }
}
