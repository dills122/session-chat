import { Component, OnInit } from '@angular/core';
import { LocalStorageService } from 'src/app/services/local-storage/local-storage.service';

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
  readonly tableData = {
    columns: ['First Name', 'Last Name', 'Age'],
    rows: [
      { firstName: 'Robert', lastName: 'Baratheon', age: 46 },
      { firstName: 'Jaime', lastName: 'Lannister', age: 31 }
    ]
  };

  constructor(private localStorageService: LocalStorageService) {
    this.loadMessages();
  }
  ngOnInit(): void {
    this.username = this.localStorageService.getItem('username');
    this.room = this.localStorageService.getItem('room');
    console.log(this.username, this.room);
  }

  private loadMessages(): void {
    this.messages = [
      {
        type: 'link',
        text: 'Now you able to use links!',
        customMessageData: {
          href: 'https://akveo.github.io/nebular/',
          text: 'Go to Nebular'
        },
        reply: false,
        date: new Date(),
        user: {
          name: 'Frodo Baggins',
          avatar: 'https://i.gifer.com/no.gif'
        }
      },
      {
        type: 'link',
        customMessageData: {
          href: 'https://akveo.github.io/ngx-admin/',
          text: 'Go to ngx-admin'
        },
        reply: true,
        date: new Date(),
        user: {
          name: 'Meriadoc Brandybuck',
          avatar: 'https://i.gifer.com/no.gif'
        }
      },
      {
        type: 'button',
        customMessageData: 'Click to scroll down',
        reply: false,
        date: new Date(),
        user: {
          name: 'Gimli Gloin',
          avatar: ''
        }
      },
      {
        type: 'table',
        text: `Now let's try to add a table`,
        customMessageData: this.tableData,
        reply: false,
        date: new Date(),
        user: {
          name: 'Fredegar Bolger',
          avatar: 'https://i.gifer.com/no.gif'
        }
      },
      {
        type: 'table',
        text: `And one more table but now in the reply`,
        customMessageData: this.tableData,
        reply: true,
        date: new Date(),
        user: {
          name: 'Fredegar Bolger',
          avatar: 'https://i.gifer.com/no.gif'
        }
      }
    ];
  }

  sendMessage(event: any) {
    this.messages.push({
      text: event.message,
      date: new Date(),
      reply: true,
      type: 'text',
      user: {
        name: this.username,
        avatar: 'https://i.gifer.com/no.gif'
      }
    });
  }
}
