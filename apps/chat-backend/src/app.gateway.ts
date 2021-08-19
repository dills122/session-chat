import {
  SubscribeMessage,
  WebSocketGateway,
  OnGatewayInit,
  OnGatewayConnection,
  OnGatewayDisconnect
} from '@nestjs/websockets';
import { Logger } from '@nestjs/common';
import { Socket } from 'socket.io';

@WebSocketGateway()
export class AppGateway implements OnGatewayInit, OnGatewayConnection, OnGatewayDisconnect {
  handleDisconnect(client: Socket): void {
    this.logger.log(`Client Disconnected ${client.id}`);
  }
  handleConnection(client: Socket): void {
    this.logger.log(`Client Connected ${client.id}`);
  }
  private logger: Logger = new Logger('AppGateway');

  afterInit(): void {
    this.logger.log('Initialized Server');
  }

  @SubscribeMessage('messageToServer')
  handleMessage(client: Socket, payload: string): void {
    client.emit('messageToClient', payload);
  }
}
