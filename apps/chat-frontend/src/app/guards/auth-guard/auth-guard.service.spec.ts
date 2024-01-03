import { TestBed } from '@angular/core/testing';
import { Router } from '@angular/router';
import { AuthVerificationService } from '../../services/auth-verification/auth-verification.service';

import { AuthGuardService } from './auth-guard.service';

describe('AuthGuardService', () => {
  let service: AuthGuardService;
  let authVerificationServiceSpy: jasmine.SpyObj<AuthVerificationService>;
  let routerSpy: jasmine.SpyObj<Router>;

  beforeEach(() => {
    authVerificationServiceSpy = jasmine.createSpyObj('AuthGuardService', ['isAuthenticated']);
    routerSpy = jasmine.createSpyObj('Router', ['navigate']);
    TestBed.configureTestingModule({
      providers: [
        {
          provide: AuthVerificationService,
          useValue: authVerificationServiceSpy
        },
        {
          provide: Router,
          useValue: routerSpy
        }
      ]
    });
    service = TestBed.inject(AuthGuardService);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });
});
