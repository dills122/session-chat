import { WebSocketGateway, WebSocketServer } from '@nestjs/websockets';
import { Server } from 'socket.io';

@WebSocketGateway(3001, {
  namespace: '/alert',
  cors: true
})
export class AlertGateway {
  @WebSocketServer() wss: Server;

  sendToAll(message: string): void {
    this.wss.emit('alertToClient', {
      type: 'Alert',
      message
    });
  }
}
