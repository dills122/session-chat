import { TestBed } from '@angular/core/testing';
import { Router } from '@angular/router';

import { LoginSessionGuardService } from './login-session-guard.service';

describe('LoginSessionGuardService', () => {
  let service: LoginSessionGuardService;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [Router]
    });
    service = TestBed.inject(LoginSessionGuardService);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });
});
