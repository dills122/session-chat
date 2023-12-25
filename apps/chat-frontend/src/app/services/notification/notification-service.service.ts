import { Injectable } from '@angular/core';
import { Socket } from 'ngx-socket-io';
import { EventTypes } from 'src/app/models/event-types';

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
    return this.socket.fromEvent<NotificationMessageFormat>(EventTypes.NOTIFICATION);
  }
}
