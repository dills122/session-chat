import { ComponentFixture, TestBed } from '@angular/core/testing';

import { GenericModalComponent } from './generic-modal.component';
import { NbDialogRef, NbDialogService } from '@nebular/theme';

describe('GenericModalComponent', () => {
  let component: GenericModalComponent;
  let fixture: ComponentFixture<GenericModalComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      declarations: [GenericModalComponent],
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
    fixture = TestBed.createComponent(GenericModalComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
