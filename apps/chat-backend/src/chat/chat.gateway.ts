import { SubscribeMessage, WebSocketGateway, OnGatewayInit, WebSocketServer } from '@nestjs/websockets';

import { Socket, Server } from 'socket.io';
import { createAdapter } from 'socket.io-redis';
import { RedisClient } from 'redis';
import { Logger } from '@nestjs/common';
import { MessageFormat } from 'src/shared/types';

@WebSocketGateway(3001, {
  cors: true,
  namespace: '/chat',
  transports: ['websocket']
})
export class ChatGateway implements OnGatewayInit {
  @WebSocketServer() wss: Server;
  private logger: Logger = new Logger('ChatGateway');

  constructor() {
    const pubClient = new RedisClient({ host: 'localhost', port: 6379 });
    const subClient = pubClient.duplicate();
    this.wss.adapter(createAdapter({ pubClient, subClient }));
  }

  afterInit(): void {
    this.logger.log('Initialized Gateway');
  }

  @SubscribeMessage('login')
  async handleLogin(client: Socket, message: MessageFormat): Promise<void> {
    try {
      this.logger.verbose('Recieved Login attempt from client', {
        room: message.room,
        uid: message.uid
      });
      await client.join(message.room);
      this.wss.in(message.room).emit('notification', {
        type: 'new-user'
      });
    } catch (err) {
      this.logger.error(err);
    }
  }

  @SubscribeMessage('logout')
  async handleLogout(client: Socket, message: MessageFormat): Promise<void> {
    try {
      this.logger.verbose('Recieved Logout attempt from client', {
        room: message.room,
        uid: message.uid
      });
      this.wss.in(message.room).emit('notification', {
        type: 'user-left',
        uid: message.uid
      });
      await client.leave(message.room);
    } catch (err) {
      this.logger.error(err);
    }
  }

  @SubscribeMessage('chatToServer')
  async handleMessage(client: Socket, message: MessageFormat): Promise<void> {
    try {
      this.logger.verbose('Recieved Message from client', {
        room: message.room,
        uid: message.uid
      });
      this.wss.in(message.room).emit('chatToClient', message);
    } catch (err) {
      this.logger.error(err);
    }
  }
}
