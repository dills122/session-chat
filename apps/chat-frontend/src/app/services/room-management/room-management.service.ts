import { Injectable } from '@angular/core';
import { Socket } from 'ngx-socket-io';
import { Observable } from 'rxjs';
import { EventTypes, SessionCreation, StatusResponseBase } from 'shared-sdk';

@Injectable({
  providedIn: 'root'
})
export class RoomManagementService {
  constructor(private socket: Socket) {}

  createSession(payload: SessionCreation) {
    this.socket.emit(EventTypes.CREATE_SESSION, payload);
  }
  subscribeSessionCreation(): Observable<StatusResponseBase> {
    return this.socket.fromEvent<StatusResponseBase>(EventTypes.CREATE_SESSION);
  }
}
