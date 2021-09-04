import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';

import { CreateSessionComponent } from './create-session/create-session.component';
import { CreateSessionRoutingModule } from './create-session-routing.module';

import {
  NbLayoutModule,
  NbCardModule,
  NbInputModule,
  NbButtonModule,
  NbIconModule,
  NbListModule,
  NbCheckboxModule,
  NbSelectModule,
  NbChatModule,
  NbFormFieldModule,
  NbTooltipModule
} from '@nebular/theme';

@NgModule({
  declarations: [CreateSessionComponent],
  imports: [
    CommonModule,
    CreateSessionRoutingModule,
    NbLayoutModule,
    NbCardModule,
    NbInputModule,
    NbButtonModule,
    NbIconModule,
    NbListModule,
    NbCheckboxModule,
    NbSelectModule,
    NbChatModule,
    NbFormFieldModule,
    FormsModule,
    NbTooltipModule
  ]
})
export class CreateSessionModule {}
