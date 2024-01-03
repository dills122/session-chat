import { Component, EventEmitter, Input, Output, ViewChild } from '@angular/core';
import { ButtonTypes } from 'src/app/models/button-types';
import { GenericModalComponent } from '../generic-modal/generic-modal.component';

@Component({
  selector: 'td-confirm-modal',
  templateUrl: './confirm-modal.component.html',
  styleUrls: ['./confirm-modal.component.scss']
})
export class ConfirmModalComponent {
  showConfirm: boolean = true;
  confirmBtnLabel: string = 'Confirm';
  confirmBtnType: ButtonTypes = ButtonTypes.SUCCESS;
  @Input({ required: true }) title: string;
  @Output() confirmEvent: EventEmitter<boolean> = new EventEmitter();
  @ViewChild('confirm_modal') private modalComponent: GenericModalComponent;

  constructor() {}

  open() {
    this.modalComponent.open();
  }

  onConfirm(event: boolean) {
    this.confirmEvent.emit(event);
  }
}
