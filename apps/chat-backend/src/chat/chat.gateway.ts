import { OnGatewayInit, SubscribeMessage, WebSocketGateway, WebSocketServer } from '@nestjs/websockets';

import { Logger } from '@nestjs/common';
import { AuthFormat, EventTypes, MessageFormat } from 'shared-sdk';
import { Server, Socket } from 'socket.io';
import {
  JwtTokenService,
  TokenValidationInput,
  UserDataInput
} from 'src/services/jwt-token/jwt-token.service';
import { Omit } from 'utility-types';
import { RoomManagementService } from 'src/services/room-management/room-management.service';

@WebSocketGateway(3001, {
  cors: true,
  namespace: '/chat',
  transports: ['websocket']
})
export class ChatGateway implements OnGatewayInit {
  @WebSocketServer() wss: Server;
  private logger: Logger = new Logger('ChatGateway');

  constructor(
    private jwtTokenService: JwtTokenService,
    private roomManagementService: RoomManagementService
  ) {}

  afterInit(): void {
    this.logger.log('Initialized Gateway');
  }

  @SubscribeMessage(EventTypes.LOGIN)
  async handleLogin(client: Socket, message: AuthFormat): Promise<void> {
    try {
      const { room, uid, referrer, isReAuth } = message;
      this.logger.verbose('Recieved Login attempt from client', {
        room: room,
        uid: uid
      });
      const token = await this.jwtTokenService.generateClientToken(message as UserDataInput);
      await client.join(message.room);
      //TODO need to create obj in Redis for Room to keep track of links used
      const isLinkExpired = this.roomManagementService.isLinkExpired(referrer);
      if (isLinkExpired) {
        client.emit(EventTypes.FAILEDLOGIN, {
          uid,
          room
        });
      } else {
        client.emit(EventTypes.LOGIN, {
          token,
          uid: uid,
          room: room,
          isReAuth: isReAuth
        });
        this.wss.in(room).emit(EventTypes.NOTIFICATION, {
          type: 'new-user'
        });
      }
    } catch (err) {
      this.logger.error(err);
    }
  }

  @SubscribeMessage(EventTypes.LOGOUT)
  async handleLogout(client: Socket, message: Omit<AuthFormat, 'referrer'>): Promise<void> {
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
