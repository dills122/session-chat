import { Injectable } from '@angular/core';
import { Socket } from 'ngx-socket-io';
import { EventTypes } from 'src/app/models/event-types';

export interface AuthFormat {
  room: string;
  uid: string;
  timestamp: string;
}

export interface AuthResponseFormat {
  room: string;
  uid: string;
  token: string;
}

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  constructor(private socket: Socket) {}

  attemptLogin(payload: AuthFormat) {
    this.socket.emit(EventTypes.LOGIN, payload);
  }
  subscribeLogin() {
    return this.socket.fromEvent<AuthResponseFormat>(EventTypes.LOGIN);
  }
  attemptLogout(payload: AuthFormat) {
    this.socket.emit(EventTypes.LOGOUT, payload);
  }
  subscribeLogout() {
    return this.socket.fromEvent<AuthFormat>(EventTypes.LOGOUT);
  }
}
