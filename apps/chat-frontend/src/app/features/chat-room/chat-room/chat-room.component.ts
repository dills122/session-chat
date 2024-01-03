import { Component, HostListener, OnDestroy, OnInit } from '@angular/core';
import { Subject } from 'rxjs';
import { map, takeUntil, tap } from 'rxjs/operators';
import { MessageFormat } from 'shared-sdk';
import { CanComponentDeactivate } from 'src/app/guards/can-deactivate.guard';
import { ChatServiceService } from 'src/app/services/chat/chat-service.service';
import { LoginService } from 'src/app/services/login/login.service';
import { SessionStorageService } from 'src/app/services/session-storage/session-storage.service';

@Component({
  selector: 'td-chat-room',
  templateUrl: './chat-room.component.html',
  providers: [],
  styles: [
    `
      ::ng-deep nb-layout-column {
        justify-content: center;
        display: flex;
      }
    `
  ]
})
export class ChatRoomComponent implements OnInit, OnDestroy, CanComponentDeactivate {
  private onDestroyNotifier = new Subject();
  public messages: any[] = [];
  private token: string;
  protected username: string;
  public room: string;
  public messages$ = this.chatService.subscribeToMessages().pipe(
    takeUntil(this.onDestroyNotifier),
    map((msg) => this.mapMessageToChatFormat(msg)),
    tap((msg) => this.messages.push(msg))
  );

  constructor(
    private sessionStorageService: SessionStorageService,
    private chatService: ChatServiceService,
    private loginService: LoginService
  ) {
    this.messages = [];
  }
  ngOnDestroy(): void {
    this.onDestroyNotifier.next(true);
    this.onDestroyNotifier.complete();
  }
  ngOnInit(): void {
    this.username = this.sessionStorageService.getItem('uid');
    this.room = this.sessionStorageService.getItem('room');
    this.token = this.sessionStorageService.getItem('jwt_token');
    this.loginService.registerLoginCallback(this.username);
    this.loginService.reAuth({
      roomId: this.room,
      uid: this.username
    });
    this.messages$.subscribe();
  }
  @HostListener('window:beforeunload')
  canDeactivate() {
    if (this.messages && this.messages.length > 0) {
      const deactivateSubject = new Subject<boolean>();
      //TODO implement a Confirm Modal here, probably need to make a generic comp at the point
      const result = confirm('Are you sure?');
      if (result) {
        return deactivateSubject;
      } else {
        return true;
      }
    } else {
      return true;
    }
  }

  mapMessageToChatFormat(msg: MessageFormat) {
    return {
      text: msg.message,
      date: new Date(msg.timestamp),
      reply: msg.uid === this.username,
      type: 'text',
      user: {
        name: msg.uid
      }
    };
  }

  sendMessage(event: any) {
    this.chatService.sendMessage({
      message: event.message,
      room: this.room,
      timestamp: new Date().toISOString(),
      uid: this.username,
      token: this.token
    });
  }
}
