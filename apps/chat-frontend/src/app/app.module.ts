import { BrowserModule } from '@angular/platform-browser';
import { NgModule } from '@angular/core';
import { RouterModule } from '@angular/router';
import { FormsModule } from '@angular/forms';
import { BrowserAnimationsModule } from '@angular/platform-browser/animations';
import {
  NbThemeModule,
  NbLayoutModule,
  NbCardModule,
  NbButtonModule,
  NbIconModule,
  NbChatModule,
  NbActionsModule,
  NbToastrModule
} from '@nebular/theme';
import { NbEvaIconsModule } from '@nebular/eva-icons';

import { AppComponent } from './app/app.component';
import { AppRoutingModule } from './app-routing.module';

import { SocketIoConfig, SocketIoModule } from 'ngx-socket-io';

import { JwtModule } from '@auth0/angular-jwt';
import { SessionStorageService } from './services/session-storage/session-storage.service';
import { CoreModule } from './core/core.module';

const config: SocketIoConfig = {
  // url: 'https://ws.dsteele.dev/chat',
  url: 'localhost:3001/chat',
  options: {
    transports: ['websocket'],
    timeout: 15000
  }
};

@NgModule({
  declarations: [AppComponent],
  imports: [
    BrowserModule,
    BrowserAnimationsModule,
    RouterModule.forRoot([], {}),
    //Global Nebular Theme/Component
    NbThemeModule.forRoot({ name: 'default' }),
    NbLayoutModule,
    NbEvaIconsModule,
    NbCardModule,
    NbButtonModule,
    NbIconModule,
    NbChatModule,
    NbActionsModule,
    NbToastrModule.forRoot(),

    FormsModule,
    CoreModule,

    // app
    AppRoutingModule,

    SocketIoModule.forRoot(config),
    JwtModule.forRoot({
      config: {
        tokenGetter: () => {
          return new SessionStorageService().getItem('jwt_token');
        }
      }
    })
  ],
  providers: [],
  bootstrap: [AppComponent]
})
export class AppModule {}
