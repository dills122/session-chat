import { OnGatewayInit, SubscribeMessage, WebSocketGateway, WebSocketServer } from '@nestjs/websockets';

import { Logger } from '@nestjs/common';
import {
  AuthFormat,
  AuthResponseFormat,
  EventStatuses,
  EventTypes,
  MessageFormat,
  NotificationTypes,
  SessionCreation,
  SessionCreationResponse
} from 'shared-sdk';
import { Server, Socket } from 'socket.io';
import {
  JwtTokenService,
  TokenValidationInput,
  UserDataInput
} from 'src/services/jwt-token/jwt-token.service';
import { NotificationService } from 'src/services/notification/notification.service';
import { RoomManagementService } from 'src/services/room-management/room-management.service';
import { Omit } from 'utility-types';

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
    private roomManagementService: RoomManagementService,
    private notificationService: NotificationService
  ) {}

  afterInit(): void {
    this.logger.log('Initialized Gateway');
  }

  @SubscribeMessage(EventTypes.CREATE_SESSION)
  async handleSessionCreation(client: Socket, message: SessionCreation): Promise<void> {
    const resp: SessionCreationResponse = {
      room: message.roomId,
      status: EventStatuses.SUCCESS
    };
    try {
      await this.roomManagementService.createSession(message);
      client.emit(EventTypes.CREATE_SESSION, resp);
    } catch (err) {
      this.logger.error(err);
      resp.status = EventStatuses.FAILED;
      client.emit(EventTypes.CREATE_SESSION, resp);
    }
  }

  @SubscribeMessage(EventTypes.LOGIN)
  async handleLogin(client: Socket, message: AuthFormat): Promise<void> {
    try {
      const { room, uid, referrer, isReAuth } = message;
      const isReferrerALink = this.roomManagementService.isReferrerALink(referrer);
      this.logger.verbose('Recieved Login attempt from client', {
        room: room,
        uid: uid
      });
      const isParticipantLinkValid = await this.roomManagementService.isParticipantLinkStillValid(referrer);
      if (isReferrerALink && !isParticipantLinkValid) {
        const failedLogin: AuthResponseFormat = {
          room,
          uid,
          status: EventStatuses.FAILED
        };
        client.emit(EventTypes.LOGIN, failedLogin);
        return;
      }
      const token = await this.jwtTokenService.generateClientToken(message as UserDataInput);
      await client.join(message.room);
      if (isReferrerALink) {
        await this.roomManagementService.updateParticipantList(room, uid);
        await this.roomManagementService.expireLink(referrer);
      }
      const login: AuthResponseFormat = {
        token,
        uid: uid,
        room: room,
        isReAuth: isReAuth,
        status: EventStatuses.SUCCESS
      };
      client.emit(EventTypes.LOGIN, login);
      this.wss.in(room).emit(
        EventTypes.NOTIFICATION,
        this.notificationService.buildNotificationMessage({
          type: NotificationTypes.NEW_USER,
          room
        })
      );
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
      this.wss.in(message.room).emit(
        EventTypes.NOTIFICATION,
        this.notificationService.buildNotificationMessage({
          type: NotificationTypes.USER_LEFT,
          room: message.room,
          data: {
            uid: message.uid
          }
        })
      );
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
      const canSendMessage = await this.roomManagementService.isParticipantAndSessionStillValid(
        message.room,
        message.uid
      );
      if (!canSendMessage) return;
      await this.jwtTokenService.validateClientToken(message as TokenValidationInput);
      this.wss.in(message.room).emit(EventTypes.RECEIVE, message);
    } catch (err) {
      this.logger.error(err);
      client.disconnect();
    }
  }
}
