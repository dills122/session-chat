import { Injectable } from '@angular/core';
import { Socket } from 'ngx-socket-io';

export interface MessageFormat {
  message: string;
  room: string;
  uid: string;
  timestamp: string;
  token: string;
}

@Injectable({
  providedIn: 'root'
})
export class ChatServiceService {
  constructor(private socket: Socket) {}
  subscribeToMessages() {
    return this.socket.fromEvent<MessageFormat>('chatToClient');
  }
  sendMessage(message: MessageFormat) {
    this.socket.emit('chatToServer', message);
  }
}
