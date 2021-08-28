import { Injectable } from '@angular/core';
import { JwtHelperService } from '@auth0/angular-jwt';
import { SessionStorageService } from '../session-storage/session-storage.service';

@Injectable({
  providedIn: 'root'
})
export class AuthVerificationService {
  constructor(private jwtHelper: JwtHelperService, private sessionStorageService: SessionStorageService) {}

  public isAuthenticated(): boolean {
    const token = this.sessionStorageService.getItem('jwt_token');
    // Check whether the token is expired and return
    // true or false
    return !this.jwtHelper.isTokenExpired(token);
  }
}
