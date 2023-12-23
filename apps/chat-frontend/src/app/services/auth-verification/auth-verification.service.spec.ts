import { TestBed } from '@angular/core/testing';
import { JwtHelperService } from '@auth0/angular-jwt';
import { SessionStorageService } from '../session-storage/session-storage.service';

import { AuthVerificationService } from './auth-verification.service';

describe('AuthVerificationService', () => {
  let service: AuthVerificationService;
  let jwtServiceSpy: jasmine.SpyObj<JwtHelperService>;
  let sessionStorageSpy: jasmine.SpyObj<SessionStorageService>;
  beforeEach(() => {
    jwtServiceSpy = jasmine.createSpyObj('JwtHelperService', ['isTokenExpired']);
    sessionStorageSpy = jasmine.createSpyObj('SessionStorageService', ['getItem']);
    TestBed.configureTestingModule({
      providers: [
        {
          provide: JwtHelperService,
          useValue: jwtServiceSpy
        },
        {
          provide: SessionStorageService,
          useValue: sessionStorageSpy
        }
      ]
    });
    service = TestBed.inject(AuthVerificationService);
    TestBed.inject(JwtHelperService);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });
  it('should return false if no token is found', () => {
    sessionStorageSpy.getItem.and.returnValue(undefined);
    const isAuthenticated = service.isAuthenticated();
    expect(isAuthenticated).toBeFalse();
  });
  it('should return true if token found and not expired', () => {
    sessionStorageSpy.getItem.and.returnValue('value');
    spyOn(service, 'isExpired').and.returnValue(false);
    const isAuthenticated = service.isAuthenticated();
    expect(isAuthenticated).toBeTrue();
  });
  it('should return false if token found but expired', () => {
    sessionStorageSpy.getItem.and.returnValue('value');
    spyOn(service, 'isExpired').and.returnValue(true);
    const isAuthenticated = service.isAuthenticated();
    expect(isAuthenticated).toBeFalse();
  });
});
