import { SubscribeMessage, WebSocketGateway, OnGatewayInit, WebSocketServer } from '@nestjs/websockets';

import { Socket, Server } from 'socket.io';
import { Logger } from '@nestjs/common';
import { AuthFormat, MessageFormat } from 'src/shared/types';
import { JwtTokenService, TokenInput } from 'src/services/jwt-token/jwt-token.service';
import { UrlShortnerService } from 'src/services/url-shortner/url-shortner.service';
import { CreateChatRoomPayload } from './models/chatroom-payload.model';
import { CreateUserUrlPayload } from './models/user-url-payload.model';
import { RedisService } from 'src/services/redis-service/redis-service.service';
import { ChatEvents } from './models/chat-events';

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
    private urlShortnerService: UrlShortnerService,
    private redisService: RedisService
  ) {}

  afterInit(): void {
    this.logger.log('Initialized Gateway');
  }

  @SubscribeMessage(ChatEvents.createChatRoom)
  async createChatRoom(client: Socket, message: CreateChatRoomPayload): Promise<void> {
    // TODO need to add this to redis through a new connection, will need to remove on chatRoomDestroy or some event
    try {
      this.logger.log('Creating chatroom', {
        roomId: message.roomId
      });
      await this.redisService.set(message.roomId, 'true');
      client.emit(ChatEvents.createChatRoom, {
        roomId: message.roomId
      });
    } catch (err) {
      this.logger.error(err);
      // TODO send error notification
    }
  }

  @SubscribeMessage(ChatEvents.createUserUrl)
  async createUserUrl(client: Socket, message: CreateUserUrlPayload): Promise<void> {
    try {
      this.logger.log('Creating short url for user', {
        roomId: message.roomId
      });
      const shortenedUrl = await this.urlShortnerService.createShortUrl(message.url);
      client.emit('createUserUrl', shortenedUrl);
    } catch (err) {
      // TODO this should emit an error notification at the very least
      this.logger.error(err);
    }
  }

  @SubscribeMessage(ChatEvents.login)
  async handleLogin(client: Socket, message: AuthFormat): Promise<void> {
    try {
      this.logger.verbose('Recieved Login attempt from client', {
        room: message.room,
        uid: message.uid
      });
      const token = await this.jwtTokenService.generateClientToken(message as TokenInput);
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

  @SubscribeMessage(ChatEvents.logout)
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

  @SubscribeMessage(ChatEvents.chatToServer)
  async handleMessage(client: Socket, message: MessageFormat): Promise<void> {
    try {
      this.logger.verbose('Recieved Message from client', {
        room: message.room,
        uid: message.uid
      });
      await this.jwtTokenService.validateClientToken(message as TokenInput);
      this.wss.in(message.room).emit('chatToClient', message);
    } catch (err) {
      this.logger.error(err);
      client.disconnect();
    }
  }
}
