import { Injectable } from '@angular/core';
import { Socket } from 'ngx-socket-io';

export interface AuthFormat {
  room: string;
  uid: string;
  timestamp: string;
}

@Injectable({
  providedIn: 'root'
})
export class AuthServiceService {
  constructor(public socket: Socket) {}

  attemptLogin(payload: AuthFormat) {
    this.socket.emit('login', payload);
  }
  subscribeLogin() {
    return this.socket.fromEvent<AuthFormat>('login');
  }
  attemptLogout(payload: AuthFormat) {
    this.socket.emit('logout', payload);
  }
  subscribeLogout() {
    return this.socket.fromEvent<AuthFormat>('logout');
  }
}
