import { TestBed } from '@angular/core/testing';
import { Router } from '@angular/router';

import { LoginSessionGuardService } from './login-session-guard.service';

describe('LoginSessionGuardService', () => {
  let service: LoginSessionGuardService;
  let routerSpy: jasmine.SpyObj<Router>;

  beforeEach(() => {
    routerSpy = jasmine.createSpyObj('Router', ['navigate']);
    TestBed.configureTestingModule({
      providers: [
        {
          provide: Router,
          useValue: routerSpy
        }
      ]
    });
    service = TestBed.inject(LoginSessionGuardService);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });
});
