import { TestBed } from '@angular/core/testing';

import { AuthVerificationService } from './auth-verification.service';

describe('AuthVerificationService', () => {
  let service: AuthVerificationService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(AuthVerificationService);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });
});
