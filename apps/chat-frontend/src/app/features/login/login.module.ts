import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';

import { LoginComponent } from './login/login.component';
import { LoginRoutingModule } from './login-routing.module';

import { NbCardModule, NbInputModule, NbButtonModule, NbIconModule, NbFormFieldModule } from '@nebular/theme';

@NgModule({
  declarations: [LoginComponent],
  imports: [
    CommonModule,
    LoginRoutingModule,
    NbCardModule,
    NbInputModule,
    NbButtonModule,
    NbIconModule,
    NbFormFieldModule,
    FormsModule
  ]
})
export class LoginModule {}
