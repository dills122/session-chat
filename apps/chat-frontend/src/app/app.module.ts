import { NgModule } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';
import { SocketIoConfig, SocketIoModule } from 'ngx-socket-io';

import { AppRoutingModule } from './app-routing.module';
import { AppComponent } from './app.component';
import { LandingPageComponent } from './landing-page/landing-page.component';
import { ChatRoomComponent } from './chat-room/chat-room.component';
import { RoomCreationComponent } from './room-creation/room-creation.component';

const config: SocketIoConfig = {
  url: 'http://localhost:3001/chat',
  options: {
    transports: ['websocket']
  }
};

@NgModule({
  declarations: [AppComponent, LandingPageComponent, ChatRoomComponent, RoomCreationComponent],
  imports: [BrowserModule, AppRoutingModule, SocketIoModule.forRoot(config)],
  providers: [],
  bootstrap: [AppComponent]
})
export class AppModule {}
