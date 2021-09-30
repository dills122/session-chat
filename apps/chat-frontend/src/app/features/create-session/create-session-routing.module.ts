import { NgModule } from '@angular/core';
import { Routes, RouterModule } from '@angular/router';

import { CreateSessionComponent } from './create-session/create-session.component';

const routes: Routes = [
  {
    path: '',
    component: CreateSessionComponent,
    data: { title: 'Create Session' }
  }
];

@NgModule({
  imports: [RouterModule.forChild(routes)],
  exports: [RouterModule]
})
export class CreateSessionRoutingModule {}
