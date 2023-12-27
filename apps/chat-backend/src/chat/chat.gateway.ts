import { SubscribeMessage, WebSocketGateway, OnGatewayInit, WebSocketServer } from '@nestjs/websockets';

import { Socket, Server } from 'socket.io';
import { Logger } from '@nestjs/common';
import { AuthFormat, MessageFormat, EventTypes } from 'shared-sdk';
import {
  JwtTokenService,
  TokenValidationInput,
  UserDataInput
} from 'src/services/jwt-token/jwt-token.service';

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

  @SubscribeMessage(EventTypes.LOGIN)
  async handleLogin(client: Socket, message: AuthFormat): Promise<void> {
    try {
      this.logger.verbose('Recieved Login attempt from client', {
        room: message.room,
        uid: message.uid
      });
      const token = await this.jwtTokenService.generateClientToken(message as UserDataInput);
      await client.join(message.room);
      client.emit(EventTypes.LOGIN, {
        token,
        uid: message.uid,
        room: message.room,
        isReAuth: message.isReAuth
      });
      this.wss.in(message.room).emit(EventTypes.NOTIFICATION, {
        type: 'new-user'
      });
    } catch (err) {
      this.logger.error(err);
    }
  }

  @SubscribeMessage(EventTypes.LOGOUT)
  async handleLogout(client: Socket, message: AuthFormat): Promise<void> {
    try {
      this.logger.verbose('Recieved Logout attempt from client', {
        room: message.room,
        uid: message.uid
      });
      this.wss.in(message.room).emit(EventTypes.NOTIFICATION, {
        type: 'user-left',
        uid: message.uid
      });
      await client.leave(message.room);
    } catch (err) {
      this.logger.error(err);
    }
  }

  @SubscribeMessage(EventTypes.SEND)
  async handleMessage(client: Socket, message: MessageFormat): Promise<void> {
    try {
      this.logger.verbose('Recieved Message from client', {
        room: message.room,
        uid: message.uid
      });
      await this.jwtTokenService.validateClientToken(message as TokenValidationInput);
      this.wss.in(message.room).emit(EventTypes.RECEIVE, message);
    } catch (err) {
      this.logger.error(err);
      client.disconnect();
    }
  }
}
