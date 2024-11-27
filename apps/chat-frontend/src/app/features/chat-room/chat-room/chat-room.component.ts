import { Component, HostListener, OnDestroy, OnInit } from '@angular/core';
import { Subject } from 'rxjs';
import { map, takeUntil, tap } from 'rxjs/operators';
import { MessageFormat } from 'shared-sdk';
import { CanComponentDeactivate } from 'src/app/guards/can-deactivate.guard';
import { ChatServiceService } from 'src/app/services/chat/chat-service.service';
import { LoginService } from 'src/app/services/login/login.service';
import { NotificationServiceService as NotificationService } from 'src/app/services/notification/notification-service.service';
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
    private loginService: LoginService,
    private notificationService: NotificationService
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
    this.notificationService.subscribeToNotifications().subscribe();
  }

  @HostListener('window:beforeunload')
  canDeactivate() {
    if (this.messages && this.messages.length > 0) {
      //TODO need to update confirm comp to be able to have a return
      const result = confirm('Are you sure you want to leave, you wont be able to come back?');
      if (result) {
        return true;
      } else {
        return false;
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
