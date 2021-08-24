import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';

import { LandingPageComponent } from './landing-page/landing-page.component';
import { ChatRoomComponent } from './chat-room/chat-room.component';
import { RoomCreationComponent } from './room-creation/room-creation.component';

const routes: Routes = [
  { path: '', component: LandingPageComponent },
  { path: 'room/:roomId', component: ChatRoomComponent },
  { path: 'room-creation', component: RoomCreationComponent }
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule]
})
export class AppRoutingModule {}
