import { Component, OnInit } from '@angular/core';
import { ChatServiceService, MessageFormat } from 'src/app/services/chat/chat-service.service';
import { SessionStorageService } from 'src/app/services/session-storage/session-storage.service';
import { map } from 'rxjs/operators';

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
      nb-chat {
        width: 500px;
      }
    `
  ]
})
export class ChatRoomComponent implements OnInit {
  public messages: any[] = [];
  private token: string;
  protected username: string;
  public room: string;
  public messages$ = this.chatService
    .subscribeToMessages()
    .pipe(map((msg) => this.mapMessageToChatFormat(msg)));

  constructor(
    private sessionStorageService: SessionStorageService,
    private chatService: ChatServiceService
  ) {}
  ngOnInit(): void {
    this.username = this.sessionStorageService.getItem('uid');
    this.room = this.sessionStorageService.getItem('room');
    this.token = this.sessionStorageService.getItem('jwt_token');
  }

  mapMessageToChatFormat(msg: MessageFormat) {
    return {
      text: msg.message,
      date: new Date(),
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
