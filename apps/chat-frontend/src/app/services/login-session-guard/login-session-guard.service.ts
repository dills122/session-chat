import { Injectable } from '@angular/core';
import { Router, ActivatedRouteSnapshot } from '@angular/router';

@Injectable({
  providedIn: 'root'
})
export class LoginSessionGuardService {
  constructor(public router: Router) {}

  canActivate(route: ActivatedRouteSnapshot): boolean {
    const { hash, rid } = route.queryParams;
    if (!(hash || rid)) {
      this.router.navigate(['home']);
      return false;
    }
    return true;
  }
}
