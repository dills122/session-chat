import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';

import { ChatRoomComponent } from './chat-room/chat-room.component';
import { ChatRoomRoutingModule } from './chat-room-routing.module';

import {
  NbCardModule,
  NbInputModule,
  NbButtonModule,
  NbIconModule,
  NbListModule,
  NbCheckboxModule,
  NbSelectModule,
  NbChatModule
} from '@nebular/theme';

@NgModule({
  declarations: [ChatRoomComponent],
  imports: [
    CommonModule,
    ChatRoomRoutingModule,
    NbCardModule,
    NbInputModule,
    NbButtonModule,
    NbIconModule,
    NbListModule,
    NbCheckboxModule,
    NbSelectModule,
    NbChatModule
  ]
})
export class ChatRoomModule {}
