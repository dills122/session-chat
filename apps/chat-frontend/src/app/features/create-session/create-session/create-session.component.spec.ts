import { ComponentFixture, TestBed } from '@angular/core/testing';

import { CreateSessionComponent } from './create-session.component';

xdescribe('CreateSessionComponent', () => {
  let component: CreateSessionComponent;
  let fixture: ComponentFixture<CreateSessionComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      declarations: [CreateSessionComponent]
    }).compileComponents();
  });

  beforeEach(() => {
    fixture = TestBed.createComponent(CreateSessionComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
