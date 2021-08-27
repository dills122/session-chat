import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';

import { SharedModule } from '../../shared/shared.module';

import { ChatRoomComponent } from './chat-room/chat-room.component';
import { ChatRoomRoutingModule } from './chat-room-routing.module';

@NgModule({
  declarations: [ChatRoomComponent],
  imports: [CommonModule, SharedModule, ChatRoomRoutingModule]
})
export class ChatRoomModule {}
