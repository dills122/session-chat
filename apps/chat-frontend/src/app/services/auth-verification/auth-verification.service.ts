import { Injectable } from '@angular/core';
import { JwtHelperService } from '@auth0/angular-jwt';
import { SessionStorageService } from '../session-storage/session-storage.service';
import * as _ from 'lodash';

@Injectable({
  providedIn: 'root'
})
export class AuthVerificationService {
  constructor(
    private jwtHelper: JwtHelperService,
    private sessionStorageService: SessionStorageService
  ) {}

  public isAuthenticated(): boolean {
    const token: string = this.sessionStorageService.getItem('jwt_token');
    if (_.isEmpty(token)) {
      return false;
    }
    return !this.isExpired(token);
  }

  public isExpired(token: string): boolean {
    return this.jwtHelper.isTokenExpired(token);
  }
}
