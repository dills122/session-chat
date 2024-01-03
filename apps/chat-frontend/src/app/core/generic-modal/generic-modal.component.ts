import { Component, EventEmitter, Input, Output, TemplateRef, ViewChild } from '@angular/core';
import { NbDialogRef, NbDialogService } from '@nebular/theme';
import { ButtonTypes } from 'src/app/models/button-types';

@Component({
  selector: 'td-generic-modal',
  templateUrl: './generic-modal.component.html',
  styleUrls: ['./generic-modal.component.scss']
})
export class GenericModalComponent {
  @Input({ required: true }) title: string;
  @Input() bodyData: string;
  @Input() confirmBtnType: ButtonTypes = ButtonTypes.GENERAL;
  @Input() showConfirm: boolean = false;
  @Input() confirmBtnLabel: string = 'Confirm';
  @Output() confirmEvent: EventEmitter<boolean> = new EventEmitter();
  @ViewChild('generic_modal') private modalContent: TemplateRef<GenericModalComponent>;
  private modalRef: NbDialogRef<GenericModalComponent>;

  constructor(private modalService: NbDialogService) {}

  confirmFunc() {
    this.close();
    this.confirmEvent.emit(true);
  }

  open() {
    this.modalRef = this.modalService.open(this.modalContent);
  }

  close() {
    this.modalRef.close();
  }
}
