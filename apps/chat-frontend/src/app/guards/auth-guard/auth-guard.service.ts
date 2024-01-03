import { Injectable } from '@angular/core';
import { AuthVerificationService } from '../../services/auth-verification/auth-verification.service';
import { Router } from '@angular/router';

@Injectable({
  providedIn: 'root'
})
export class AuthGuardService {
  constructor(
    public auth: AuthVerificationService,
    public router: Router
  ) {}

  canActivate(): boolean {
    if (!this.auth.isAuthenticated()) {
      this.router.navigate(['login']);
      return false;
    }
    return true;
  }
}
