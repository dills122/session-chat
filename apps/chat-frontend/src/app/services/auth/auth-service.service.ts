import { Injectable } from '@angular/core';
import { Socket } from 'ngx-socket-io';
import { EventTypes, AuthFormat, AuthResponseFormat } from 'shared-sdk';

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
