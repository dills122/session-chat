import { Component, Input, ViewChild } from '@angular/core';
import { ButtonTypes } from 'src/app/models/button-types';
import { GenericModalComponent } from '../generic-modal/generic-modal.component';

@Component({
  selector: 'td-confirm-modal',
  templateUrl: './confirm-modal.component.html'
})
export class ConfirmModalComponent {
  showConfirm: boolean = true;
  confirmBtnLabel: string = 'Confirm';
  confirmBtnType: ButtonTypes = ButtonTypes.SUCCESS;
  @Input({ required: true }) title: string;
  @Input() confirmAction: (args?: any) => void; //TODO maybe update args
  @ViewChild('confirm_modal') private modalComponent: GenericModalComponent;

  constructor() {}

  open() {
    this.modalComponent.open();
  }
}
