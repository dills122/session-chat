import { NgModule } from "@angular/core";
import { Routes, RouterModule, PreloadAllModules } from "@angular/router";

const routes: Routes = [
  {
    path: "",
    redirectTo: "chat-room",
    pathMatch: "full",
  },
  {
    path: "chat-room",
    loadChildren: () =>
      import("./features/chat-room/chat-room.module").then(
        (m) => m.ChatRoomModule
      ),
  },
  {
    path: "**",
    redirectTo: "chat-room",
  },
];

@NgModule({
  imports: [
    RouterModule.forRoot(routes, {
      scrollPositionRestoration: "enabled",
      preloadingStrategy: PreloadAllModules,
      relativeLinkResolution: "legacy",
    }),
  ],
  exports: [RouterModule],
})
export class AppRoutingModule {}
