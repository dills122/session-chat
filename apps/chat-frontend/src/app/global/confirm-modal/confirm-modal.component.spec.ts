import { ComponentFixture, TestBed } from '@angular/core/testing';

import { ConfirmModalComponent } from './confirm-modal.component';
import { GenericModalComponent } from '../generic-modal/generic-modal.component';
import { NbDialogRef, NbDialogService } from '@nebular/theme';

describe('ConfirmModalComponent', () => {
  let component: ConfirmModalComponent;
  let fixture: ComponentFixture<ConfirmModalComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      declarations: [ConfirmModalComponent, GenericModalComponent],
      providers: [
        {
          provide: NbDialogService,
          useValue: {
            open: () => {
              return {
                close: () => {}
              } as NbDialogRef<GenericModalComponent>;
            }
          }
        }
      ]
    });
    fixture = TestBed.createComponent(ConfirmModalComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
