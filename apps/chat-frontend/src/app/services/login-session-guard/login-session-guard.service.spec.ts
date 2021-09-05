import { TestBed } from '@angular/core/testing';

import { LoginSessionGuardService } from './login-session-guard.service';

describe('LoginSessionGuardService', () => {
  let service: LoginSessionGuardService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(LoginSessionGuardService);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });
});
