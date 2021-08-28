import { BrowserModule } from "@angular/platform-browser";
import { NgModule } from "@angular/core";
import { RouterModule } from "@angular/router";
import { FormsModule } from "@angular/forms";
import { BrowserAnimationsModule } from "@angular/platform-browser/animations";
import {
  NbThemeModule,
  NbLayoutModule,
  NbCardModule,
  NbInputModule,
  NbButtonModule,
  NbIconModule,
  NbListModule,
  NbCheckboxModule,
  NbSelectModule,
  NbChatModule,
} from "@nebular/theme";
import { NbEvaIconsModule } from "@nebular/eva-icons";

import { AppComponent } from "./app/app.component";
import { AppRoutingModule } from "./app-routing.module";

import { SocketIoConfig, SocketIoModule } from "ngx-socket-io";

const config: SocketIoConfig = {
  url: "http://localhost:3001/chat",
  options: {
    transports: ["websocket"],
  },
};

@NgModule({
  declarations: [AppComponent],
  imports: [
    BrowserModule,
    BrowserAnimationsModule,
    RouterModule.forRoot([], { relativeLinkResolution: "legacy" }),
    NbThemeModule.forRoot({ name: "default" }),
    NbLayoutModule,
    NbEvaIconsModule,
    NbCardModule,
    NbInputModule,
    NbButtonModule,
    NbIconModule,
    NbListModule,
    NbCheckboxModule,
    NbSelectModule,
    FormsModule,
    NbChatModule,

    // app
    AppRoutingModule,

    SocketIoModule.forRoot(config),
  ],
  providers: [],
  bootstrap: [AppComponent],
})
export class AppModule {}
