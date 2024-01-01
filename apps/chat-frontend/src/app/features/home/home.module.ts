import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';

import { HomeComponent } from './home/home.component';
import { HomeRoutingModule } from './home-routing.module';

import { NbCardModule, NbButtonModule } from '@nebular/theme';

@NgModule({
  declarations: [HomeComponent],
  imports: [CommonModule, HomeRoutingModule, NbCardModule, NbButtonModule]
})
export class HomeModule {}
