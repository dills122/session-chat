import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { GenericModalComponent } from './generic-modal/generic-modal.component';
import { NbDialogModule, NbCardModule, NbButtonModule } from '@nebular/theme';
import { ConfirmModalComponent } from './confirm-modal/confirm-modal.component';

@NgModule({
  declarations: [GenericModalComponent, ConfirmModalComponent],
  imports: [CommonModule, NbCardModule, NbButtonModule, NbDialogModule.forChild()],
  exports: [GenericModalComponent, ConfirmModalComponent]
})
export class CoreModule {}
