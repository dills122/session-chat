import { Injectable } from '@angular/core';
import { Socket } from 'ngx-socket-io';
import { EventTypes } from 'src/app/models/event-types';

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
    return this.socket.fromEvent<MessageFormat>(EventTypes.RECEIVE);
  }
  sendMessage(message: MessageFormat) {
    this.socket.emit(EventTypes.SEND, message);
  }
}
