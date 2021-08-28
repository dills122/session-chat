import { SubscribeMessage, WebSocketGateway, OnGatewayInit, WebSocketServer } from '@nestjs/websockets';

import { Socket, Server } from 'socket.io';
import { Logger } from '@nestjs/common';
import { AuthFormat, MessageFormat } from 'src/shared/types';
import { JwtTokenService } from 'src/services/jwt-token/jwt-token.service';

@WebSocketGateway(3001, {
  cors: true,
  namespace: '/chat',
  transports: ['websocket']
})
export class ChatGateway implements OnGatewayInit {
  @WebSocketServer() wss: Server;
  private logger: Logger = new Logger('ChatGateway');

  constructor(private jwtTokenService: JwtTokenService) {}

  afterInit(): void {
    this.logger.log('Initialized Gateway');
  }

  @SubscribeMessage('login')
  async handleLogin(client: Socket, message: AuthFormat): Promise<void> {
    try {
      this.logger.verbose('Recieved Login attempt from client', {
        room: message.room,
        uid: message.uid
      });
      const token = await this.jwtTokenService.generateClientToken(message.uid);
      await client.join(message.room);
      client.emit('login', {
        token,
        uid: message.uid,
        room: message.room
      });
      this.wss.in(message.room).emit('notification', {
        type: 'new-user'
      });
    } catch (err) {
      this.logger.error(err);
    }
  }

  @SubscribeMessage('logout')
  async handleLogout(client: Socket, message: AuthFormat): Promise<void> {
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
