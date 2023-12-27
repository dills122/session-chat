import { NgModule } from '@angular/core';
import { Routes, RouterModule, PreloadAllModules } from '@angular/router';
import { AuthGuardService as AuthGuard } from './services/auth-guard/auth-guard.service';
import { LoginSessionGuardService } from './services/login-session-guard/login-session-guard.service';
import { ChatRoomComponent } from './features/chat-room/chat-room/chat-room.component';

const routes: Routes = [
  {
    path: '',
    redirectTo: 'home',
    pathMatch: 'full'
  },
  {
    path: 'chat-room',
    loadChildren: () => import('./features/chat-room/chat-room.module').then((m) => m.ChatRoomModule),
    canActivate: [AuthGuard],
    canDeactivate: [(comp: ChatRoomComponent) => comp.messages.length <= 0] //TODO might want to add more checks
  },
  {
    path: 'login',
    loadChildren: () => import('./features/login/login.module').then((m) => m.LoginModule),
    canActivate: [LoginSessionGuardService]
  },
  {
    path: 'create-session',
    loadChildren: () =>
      import('./features/create-session/create-session.module').then((m) => m.CreateSessionModule)
  },
  {
    path: 'home',
    loadChildren: () => import('./features/home/home.module').then((m) => m.HomeModule)
  },
  {
    path: '**',
    redirectTo: 'home'
  }
];

@NgModule({
  imports: [
    RouterModule.forRoot(routes, {
      scrollPositionRestoration: 'enabled',
      preloadingStrategy: PreloadAllModules
    })
  ],
  exports: [RouterModule]
})
export class AppRoutingModule {}
