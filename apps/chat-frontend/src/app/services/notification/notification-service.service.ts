import { Injectable } from '@angular/core';
import { Socket } from 'ngx-socket-io';

export interface NotificationMessageFormat {
  type: string;
  room: string;
  uid: string;
  timestamp: string;
}

@Injectable({
  providedIn: 'root'
})
export class NotificationServiceService {
  constructor(private socket: Socket) {}
  subscribeToNotifications() {
    return this.socket.fromEvent<NotificationMessageFormat>('notification');
  }
}
