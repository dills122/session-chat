import { Component, OnInit } from '@angular/core';
import { ChatServiceService, MessageFormat } from 'src/app/services/chat/chat-service.service';
import { SessionStorageService } from 'src/app/services/session-storage/session-storage.service';

@Component({
  selector: 'nb-chat-room',
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
  messages: any[] = [];
  protected username: string;
  public room: string;

  constructor(
    private sessionStorageService: SessionStorageService,
    private chatService: ChatServiceService
  ) {}
  ngOnInit(): void {
    this.username = this.sessionStorageService.getItem('uid');
    this.room = this.sessionStorageService.getItem('room');
    console.log(this.username, this.room);
    this.listenForMessages();
  }

  private listenForMessages() {
    this.chatService.subscribeToMessages().subscribe((msg) => {
      return this.messages.push(this.mapMessageToChatFormat(msg));
    });
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
    this.messages.push();
    this.chatService.sendMessage({
      message: event.message,
      room: this.room,
      timestamp: new Date().toISOString(),
      uid: this.username
    });
  }
}
